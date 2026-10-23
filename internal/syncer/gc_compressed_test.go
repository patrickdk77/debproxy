package syncer_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func gzipString(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func zstdString(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w, err := zstd.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func xzString(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w, err := xz.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

const gcPoolFile = "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
const gcPackages = "Package: libfoo\nVersion: 1.0\nFilename: " + gcPoolFile + "\n\n"

// TestGCPoolReferencedByCompressedPackagesIndexKept is the regression test
// for the snapshot data-loss bug. Snapshots publish compressed indexes
// only, and a reference scan that read the plain file alone saw no
// references and let GC delete every package a retained snapshot named.
func TestGCPoolReferencedByCompressedPackagesIndexKept(t *testing.T) {
	variants := map[string]string{
		"Packages.gz":  gzipString(t, gcPackages),
		"Packages.zst": zstdString(t, gcPackages),
		"Packages.xz":  xzString(t, gcPackages),
	}
	for name, content := range variants {
		t.Run(name, func(t *testing.T) {
			store := newMockStorage()
			idx := &mockIndex{}
			s := newTestSyncer(store, idx, "ubuntu", "jammy")
			store.poolFiles[gcPoolFile] = struct{}{}
			store.publishedFiles["current/ubuntu/dists/jammy/main/binary-amd64/"+name] = content

			if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
				t.Fatalf("Cleanup: %v", err)
			}
			if contains(store.deleted, gcPoolFile) {
				t.Fatalf("pool file referenced only by %s was deleted", name)
			}
		})
	}
}

// TestGCPoolReadsOneVariantPerDirectory: when several forms of the same
// index are present, the scan must still find the reference exactly
// once and must not fail on the forms it did not pick.
func TestGCPoolReadsOneVariantPerDirectory(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	store.poolFiles[gcPoolFile] = struct{}{}
	dir := "current/ubuntu/dists/jammy/main/binary-amd64/"
	store.publishedFiles[dir+"Packages"] = gcPackages
	store.publishedFiles[dir+"Packages.gz"] = gzipString(t, gcPackages)
	store.publishedFiles[dir+"Packages.zst"] = zstdString(t, gcPackages)

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if contains(store.deleted, gcPoolFile) {
		t.Fatal("referenced pool file deleted with all variants present")
	}
}

// TestGCPoolCorruptIndexAbortsRun covers the error path: an index that
// cannot be decoded means the reference set is incomplete, and GC must
// refuse to delete anything rather than treat the unreadable snapshot as
// referencing nothing.
func TestGCPoolCorruptIndexAbortsRun(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	store.poolFiles[gcPoolFile] = struct{}{}
	orphan := "pool/ubuntu/jammy/upstream/main/o/orphan/orphan_1.0_amd64.deb"
	store.poolFiles[orphan] = struct{}{}
	store.publishedFiles["current/ubuntu/dists/jammy/main/binary-amd64/Packages.gz"] = "not gzip at all"

	err := s.Cleanup(context.Background(), 0, 0, time.Now())
	if err == nil {
		t.Fatal("Cleanup succeeded with an unreadable index")
	}
	if len(store.deleted) != 0 {
		t.Fatalf("deleted %v despite an unreadable index", store.deleted)
	}
}

// TestGCPoolUnreferencedStillCollected guards the other direction: the
// compressed-variant support must not have made GC keep everything.
func TestGCPoolUnreferencedStillCollected(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	store.poolFiles[gcPoolFile] = struct{}{}
	orphan := "pool/ubuntu/jammy/upstream/main/o/orphan/orphan_1.0_amd64.deb"
	store.poolFiles[orphan] = struct{}{}
	store.publishedFiles["current/ubuntu/dists/jammy/main/binary-amd64/Packages.gz"] = gzipString(t, gcPackages)

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if contains(store.deleted, gcPoolFile) {
		t.Fatal("referenced file deleted")
	}
	if !contains(store.deleted, orphan) {
		t.Fatal("unreferenced file was not collected")
	}
}

// TestGCSrcReferencedByCompressedSourcesIndexKept is the source-side
// twin of the Packages test.
func TestGCSrcReferencedByCompressedSourcesIndexKept(t *testing.T) {
	srcFile := "src/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0.dsc"
	sources := "Package: libfoo\nVersion: 1.0\nDirectory: src/ubuntu/jammy/upstream/main/l/libfoo\nFiles:\n abc 100 libfoo_1.0.dsc\n\n"
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	store.publishedFiles[srcFile] = "dsc content"
	store.publishedFiles["current/ubuntu/dists/jammy/main/source/Sources.gz"] = gzipString(t, sources)

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if contains(store.deleted, srcFile) {
		t.Fatal("source file referenced only by Sources.gz was deleted")
	}
}

// TestGCInvalidatesExistsCacheForDeletedFile is the regression test for a
// stale positive in the exists cache outliving the file: Ingestor.Cache
// trusts that cache to skip a download, so after GC removes a pool file
// the cache must forget it.
func TestGCInvalidatesExistsCacheForDeletedFile(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	orphan := "pool/ubuntu/jammy/upstream/main/o/orphan/orphan_1.0_amd64.deb"
	store.poolFiles[orphan] = struct{}{}
	s.ExistsCache().Add(orphan)
	if !s.ExistsCache().Has(orphan) {
		t.Fatal("setup: exists cache did not record the path")
	}

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !contains(store.deleted, orphan) {
		t.Fatal("orphan was not collected; test proves nothing")
	}
	if s.ExistsCache().Has(orphan) {
		t.Fatal("exists cache still reports the deleted file as present")
	}
}

// TestGCKeepsExistsCacheForSurvivingFile: invalidation must be scoped to
// what was actually deleted.
func TestGCKeepsExistsCacheForSurvivingFile(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	store.poolFiles[gcPoolFile] = struct{}{}
	store.publishedFiles["current/ubuntu/dists/jammy/main/binary-amd64/Packages.gz"] = gzipString(t, gcPackages)
	s.ExistsCache().Add(gcPoolFile)

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !s.ExistsCache().Has(gcPoolFile) {
		t.Fatal("exists cache lost a file that survived GC")
	}
}

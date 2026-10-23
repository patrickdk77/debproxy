package syncer_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/syncer"
)

const fakeSHA = "0000000000000000000000000000000000000000000000000000000000000000"

func putPool(t *testing.T, ctx context.Context, store *filesystem.Store, p, content string) {
	t.Helper()
	if err := store.PutFile(ctx, p, bytes.NewReader([]byte(content)), int64(len(content))); err != nil {
		t.Fatalf("PutFile %s: %v", p, err)
	}
}

func entryFor(pkg, ver, pool string) model.IndexEntry {
	// Control is what publishing writes out verbatim, so it must carry the
	// Filename line exactly as a real entry (built from the upstream
	// stanza with Filename rewritten to the pool path) would.
	control := "Package: " + pkg + "\nVersion: " + ver + "\nArchitecture: amd64\n" +
		"Filename: " + pool + "\nSize: 4\nSHA256: " + fakeSHA + "\n"
	return model.IndexEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
		Package: pkg, Version: ver, Upstream: "upstream",
		PoolPath:  pool,
		Size:      4,
		Checksums: model.Checksums{SHA256: fakeSHA},
		Control:   control,
	}
}

// publishedNames reads one compressed Packages index out of the store and
// returns every Filename: it carries, so a test can prove the snapshot
// really references what it expects before asserting on GC.
func publishedNames(t *testing.T, ctx context.Context, store *filesystem.Store, dir string) []string {
	t.Helper()
	files, err := store.ListPublished(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		base := f[strings.LastIndex(f, "/")+1:]
		if base != "Packages.gz" {
			continue
		}
		raw, err := store.OpenPublished(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		rc, err := apt.OpenCompressed(f, raw)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, line := range strings.Split(string(data), "\n") {
			if fn, ok := strings.CutPrefix(line, "Filename: "); ok {
				names = append(names, fn)
			}
		}
		return names
	}
	t.Fatalf("no Packages.gz under %s: %v", dir, files)
	return nil
}

// TestSnapshotThenCleanupKeepsPackagesTheSnapshotReferences is the
// end-to-end regression for the snapshot data-loss bug, driven through
// the real filesystem store, the real deb822 index, the real Snapshot
// publisher and the real Cleanup. The published snapshot carries only
// compressed Packages indexes; after a newer version supersedes the one
// the snapshot names, GC must still keep the superseded file because the
// retained snapshot points at it.
func TestSnapshotThenCleanupKeepsPackagesTheSnapshotReferences(t *testing.T) {
	ctx := context.Background()
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb822store.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	s := syncer.New(minimalConfig("ubuntu", "jammy"), store, index, nil, nil, nil, nil)

	v1 := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	putPool(t, ctx, store, v1, "deb1")
	if err := index.UpsertEntry(ctx, entryFor("libfoo", "1.0", v1)); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	if err := s.Snapshot(ctx, now); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Document the trigger: the snapshot must have published an index, and
	// it must be a compressed one, since that is the shape the bug hid in.
	snapID := now.Format(syncer.SnapshotIDFormat)
	published, err := store.ListPublished(ctx, snapID+"/ubuntu/dists/jammy/main/binary-amd64")
	if err != nil {
		t.Fatal(err)
	}
	var sawIndex, sawPlain bool
	for _, p := range published {
		base := p[strings.LastIndex(p, "/")+1:]
		if strings.HasPrefix(base, "Packages") {
			sawIndex = true
		}
		if base == "Packages" {
			sawPlain = true
		}
	}
	if !sawIndex {
		t.Fatalf("snapshot published no Packages index at all: %v", published)
	}
	if sawPlain {
		t.Logf("note: snapshot also published a plain Packages file; the regression still exercises the compressed path via current/")
	}
	// Verify the extraction: the snapshot's index must name v1, or the GC
	// assertion below would be testing an empty index rather than the bug.
	names := publishedNames(t, ctx, store, snapID+"/ubuntu/dists/jammy/main/binary-amd64")
	if len(names) != 1 || names[0] != v1 {
		t.Fatalf("snapshot index names %v, want exactly [%s]", names, v1)
	}

	// A newer version supersedes 1.0 in the index, so the index alone no
	// longer protects v1's pool file. Only the snapshot does.
	v2 := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_2.0_amd64.deb"
	putPool(t, ctx, store, v2, "deb2")
	if err := index.UpsertEntry(ctx, entryFor("libfoo", "2.0", v2)); err != nil {
		t.Fatal(err)
	}

	// A genuinely orphaned file: never indexed, never in any snapshot.
	orphan := "pool/ubuntu/jammy/upstream/main/o/orphan/orphan_1.0_amd64.deb"
	putPool(t, ctx, store, orphan, "junk")

	// Run well past the GC grace period so age cannot be what saves v1.
	if err := s.Cleanup(ctx, 0, 0, now.Add(48*time.Hour)); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	for _, p := range []string{v1, v2} {
		ok, err := store.Exists(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%s was collected although a retained snapshot references it", p)
		}
	}
	ok, err := store.Exists(ctx, orphan)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("orphan %s survived; GC did not run at all", orphan)
	}
}

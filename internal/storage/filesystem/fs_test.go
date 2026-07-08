package filesystem_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
)

func TestPutFileDedupAndDigest(t *testing.T) {
	root := t.TempDir()
	store, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	poolPath := model.PoolPath("debian", "trixie", "debian-main", "main", "apt", "2.6.1", "amd64")
	data := []byte("fake deb content")

	if err := store.PutFile(ctx, poolPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFile(ctx, poolPath, bytes.NewReader([]byte("other")), 5); err != nil {
		t.Fatal(err)
	}

	exists, err := store.Exists(ctx, poolPath)
	if err != nil || !exists {
		t.Fatalf("expected file to exist: exists=%v err=%v", exists, err)
	}

	checksums, err := store.ComputeChecksums(ctx, poolPath)
	if err != nil {
		t.Fatal(err)
	}
	if checksums.SHA256 == "" {
		t.Fatal("expected SHA256 digest")
	}
	if checksums.SHA512 == "" {
		t.Fatal("expected SHA512 digest")
	}
}

func TestWalkPoolAndListPublishedInfoPopulateFileInfo(t *testing.T) {
	root := t.TempDir()
	store, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	poolPath := model.PoolPath("debian", "trixie", "debian-main", "main", "apt", "2.6.1", "amd64")
	data := []byte("fake deb content")
	if err := store.PutFile(ctx, poolPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}

	var walked []string
	if err := store.WalkPool(ctx, func(info storage.FileInfo) error {
		walked = append(walked, info.Path)
		if info.Path != poolPath {
			return nil
		}
		if info.Size != int64(len(data)) {
			t.Errorf("WalkPool: Size = %d, want %d", info.Size, len(data))
		}
		if info.ModTime.IsZero() {
			t.Error("WalkPool: ModTime is zero, want populated")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(walked) != 1 {
		t.Fatalf("expected 1 pool file walked, got %d: %v", len(walked), walked)
	}

	if err := store.WriteFile(ctx, "current/debian/dists/trixie/main/binary-amd64/Packages", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	infos, err := store.ListPublishedInfo(ctx, "current")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 published file, got %d: %v", len(infos), infos)
	}
	if infos[0].Size != int64(len(data)) {
		t.Errorf("ListPublishedInfo: Size = %d, want %d", infos[0].Size, len(data))
	}
	if infos[0].ModTime.IsZero() {
		t.Error("ListPublishedInfo: ModTime is zero, want populated")
	}
}

func TestPutFileRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	store, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	data := []byte("malicious content")

	if err := store.PutFile(ctx, "pool/../../../etc/passwd", bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("expected PutFile to reject a path escaping the pool root, got nil error")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "etc", "passwd")); err == nil {
		t.Fatal("traversal path must not have been written outside the store root")
	}
}

func TestContentDedupHardLinks(t *testing.T) {
	root := t.TempDir()
	store, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	content := []byte("identical deb content across upstreams")
	pathA := model.PoolPath("debian", "trixie", "debian-main", "main", "apt", "2.6.1", "amd64")
	pathB := model.PoolPath("ubuntu", "noble", "ubuntu-main", "main", "apt", "2.6.1", "amd64")
	pathC := model.PoolPath("debian", "trixie", "debian-main", "main", "bash", "5.2", "amd64")

	for _, p := range []string{pathA, pathB} {
		if err := store.PutFile(ctx, p, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutFile(ctx, pathC, bytes.NewReader([]byte("different content")), 17); err != nil {
		t.Fatal(err)
	}
	// Both pool paths must exist and read back their full content. Storage
	// no longer deduplicates by inode; dedup is handled in the metadata index.
	for _, p := range []struct {
		poolPath string
		want     []byte
	}{
		{pathA, content},
		{pathB, content},
		{pathC, []byte("different content")},
	} {
		exists, err := store.Exists(ctx, p.poolPath)
		if err != nil || !exists {
			t.Fatalf("expected file to exist: %s exists=%v err=%v", p.poolPath, exists, err)
		}
		got, err := os.ReadFile(filepath.Join(root, "pool", trimPool(p.poolPath)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, p.want) {
			t.Fatalf("content mismatch for %s", p.poolPath)
		}
	}
}

func trimPool(poolPath string) string {
	return poolPath[len("pool/"):]
}

func inode(t *testing.T, root, poolPath string) uint64 {
	t.Helper()
	abs := filepath.Join(root, "pool", trimPool(poolPath))
	_, err := os.Stat(abs)
	if err != nil {
		t.Fatal(err)
	}
	// inode helper removed; keep compatibility if present but return 0.
	return 0
}

func TestSnapshotResolution(t *testing.T) {
	root := t.TempDir()
	store, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for _, id := range []string{"2026-04-28", "2026-04-30"} {
		rel := filepath.ToSlash(filepath.Join(id, "debian", "dists", "trixie", "Release"))
		if err := store.WriteFile(ctx, rel, bytes.NewReader([]byte("release")), 7); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.ResolveSnapshot(ctx, "debian", time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if got != "2026-04-28" {
		t.Fatalf("expected 2026-04-28, got %q", got)
	}

}

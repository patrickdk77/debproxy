package deb822store_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
)

func newStore(t *testing.T) (*deb822store.Store, string) {
	t.Helper()
	root := t.TempDir()
	fs, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := deb822store.New(context.Background(), fs)
	if err != nil {
		t.Fatal(err)
	}
	return s, root
}

func entry(pkg, version, arch string) model.IndexEntry {
	return model.IndexEntry{
		OS:        "debian",
		Codename:  "trixie",
		Component: "main",
		Arch:      arch,
		Package:   pkg,
		Version:   version,
		Upstream:  "debian-main",
		PoolPath:  model.PoolPath("debian", "trixie", "debian-main", "main", pkg, version, arch),
		Checksums: model.Checksums{SHA256: model.Digest("aa" + pkg + version + arch)},
		Size:      1234,
		Control:   "Package: " + pkg + "\nVersion: " + version + "\nArchitecture: " + arch + "\n",
	}
}

func TestUpsertAndList(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	e := entry("apt", "2.6.1", "amd64")
	if err := s.UpsertEntry(ctx, e); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "apt" {
		t.Fatalf("expected 1 apt entry, got %v", entries)
	}
}

func TestUpsertUpdatesExisting(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	e := entry("apt", "2.6.1", "amd64")
	if err := s.UpsertEntry(ctx, e); err != nil {
		t.Fatal(err)
	}

	e2 := e
	e2.Size = 9999
	if err := s.UpsertEntry(ctx, e2); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListEntries(ctx, model.Selector{OS: "debian"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after upsert, got %d", len(entries))
	}
	if entries[0].Size != 9999 {
		t.Fatalf("expected updated size 9999, got %d", entries[0].Size)
	}
}

func TestEntryByDigest(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	e := entry("curl", "7.88", "amd64")
	e.Checksums.SHA256 = "deadbeefdeadbeef"
	if err := s.UpsertEntry(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, err := s.EntryByDigest(ctx, "deadbeefdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Package != "curl" {
		t.Fatalf("expected curl entry by digest, got %v", got)
	}

	missing, err := s.EntryByDigest(ctx, "notexist")
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Fatal("expected nil for unknown digest")
	}
}

func TestFindEntry(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	old := entry("bash", "5.1", "amd64")
	newer := entry("bash", "5.2", "amd64")
	if err := s.UpsertEntry(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEntry(ctx, newer); err != nil {
		t.Fatal(err)
	}

	// empty version -> highest wins
	got, err := s.FindEntry(ctx, model.Selector{OS: "debian", Codename: "trixie"}, "bash", "")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Version != "5.2" {
		t.Fatalf("expected version 5.2, got %v", got)
	}

	// exact version lookup
	exact, err := s.FindEntry(ctx, model.Selector{OS: "debian"}, "bash", "5.1")
	if err != nil {
		t.Fatal(err)
	}
	if exact == nil || exact.Version != "5.1" {
		t.Fatalf("expected version 5.1, got %v", exact)
	}

	// not found
	none, err := s.FindEntry(ctx, model.Selector{}, "nosuchpkg", "")
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("expected nil for unknown package")
	}
}

func TestSelectorFiltering(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	// Two different codenames
	e1 := entry("apt", "2.6.1", "amd64")
	e1.Codename = "trixie"
	e2 := entry("apt", "2.5.0", "amd64")
	e2.Codename = "bookworm"
	if err := s.UpsertEntry(ctx, e1); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEntry(ctx, e2); err != nil {
		t.Fatal(err)
	}

	trixie, err := s.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie"})
	if err != nil {
		t.Fatal(err)
	}
	if len(trixie) != 1 || trixie[0].Version != "2.6.1" {
		t.Fatalf("expected 1 trixie entry at 2.6.1, got %v", trixie)
	}

	all, err := s.ListEntries(ctx, model.Selector{OS: "debian"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 entries across codenames, got %d", len(all))
	}
}

func TestFlushAndReload(t *testing.T) {
	root := t.TempDir()
	fs, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s, err := deb822store.New(ctx, fs)
	if err != nil {
		t.Fatal(err)
	}

	e := entry("wget", "1.21", "amd64")
	e.Checksums.SHA256 = "abc123"
	if err := s.UpsertEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUpstreamState(ctx, model.UpstreamPackageState{
		Upstream:        "debian-main",
		PackageName:     "wget",
		Arch:            "amd64",
		UpstreamVersion: "1.21",
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	// Reload from the same storage backend  --  must recover all state.
	s2, err := deb822store.New(ctx, fs)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := s2.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "wget" {
		t.Fatalf("expected wget after reload, got %v", entries)
	}

	st, err := s2.GetUpstreamState(ctx, "debian-main", "wget", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.UpstreamVersion != "1.21" {
		t.Fatalf("expected upstream state after reload, got %v", st)
	}
}

// hookStorage wraps a real storage.Storage and calls onWriteFile synchronously
// before delegating, letting a test inject a mutation at the exact moment a
// write to the backend is in flight -- deterministically, with no goroutines
// or sleeps needed.
type hookStorage struct {
	storage.Storage
	onWriteFile func(relPath string)
}

func (h *hookStorage) WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error {
	if h.onWriteFile != nil {
		fn := h.onWriteFile
		h.onWriteFile = nil // fire once so writing the second flush's data doesn't recurse
		fn(relPath)
	}
	return h.Storage.WriteFile(ctx, relPath, r, size)
}

// TestFlushDoesNotLoseConcurrentUpsert proves the generation-counter fix for
// the Flush/writeRelPath lost-update race: writeRelPath snapshots entries
// under RLock, writes to the backend without holding any lock, and Flush used
// to unconditionally clear the dirty flag afterward. A mutation landing in
// that window used to be silently marked clean without ever being persisted.
func TestFlushDoesNotLoseConcurrentUpsert(t *testing.T) {
	root := t.TempDir()
	fsBackend, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	hook := &hookStorage{Storage: fsBackend}
	s, err := deb822store.New(ctx, hook)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpsertEntry(ctx, entry("apt", "1.0", "amd64")); err != nil {
		t.Fatal(err)
	}

	// Fires while Flush's write for this key is in flight -- after
	// writeRelPath already snapshotted the entries slice for writing.
	hook.onWriteFile = func(relPath string) {
		if err := s.UpsertEntry(ctx, entry("bash", "5.2", "amd64")); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.Flush(ctx); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	// "bash" raced with the write and must still be marked dirty; a second
	// flush should pick it up rather than it having been silently dropped.
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("second flush: %v", err)
	}

	reloaded, err := deb822store.New(ctx, fsBackend)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := reloaded.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	var gotApt, gotBash bool
	for _, e := range entries {
		if e.Package == "apt" {
			gotApt = true
		}
		if e.Package == "bash" {
			gotBash = true
		}
	}
	if !gotApt || !gotBash {
		t.Fatalf("expected both apt and bash to survive the race, got entries=%v", entries)
	}
}

// TestRefreshDoesNotDiscardPendingWriteOnExternalDelete proves evictFile no
// longer wipes in-memory content for a key that still has an unflushed local
// mutation. Refresh's own doc comment promises "no pending writes are lost";
// evictFile used to violate that when the backing file disappeared externally
// while a dirty (unflushed) mutation was pending for the same key.
func TestRefreshDoesNotDiscardPendingWriteOnExternalDelete(t *testing.T) {
	root := t.TempDir()
	fs, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s, err := deb822store.New(ctx, fs)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpsertEntry(ctx, entry("apt", "1.0", "amd64")); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	// A second local mutation, not yet flushed -- dirty[relPath] is true.
	if err := s.UpsertEntry(ctx, entry("bash", "5.2", "amd64")); err != nil {
		t.Fatal(err)
	}

	// Simulate the backing file disappearing externally (e.g. another
	// instance/process deleted it) while our pending write hasn't landed yet.
	relPath := "metadata/index/debian/trixie/main/amd64.packages.zst"
	if err := fs.DeletePublished(ctx, relPath); err != nil {
		t.Fatal(err)
	}

	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected apt and bash to survive Refresh's eviction of a dirty key, got %v", entries)
	}

	// Flushing now must recreate the file with both entries.
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	reloaded, err := deb822store.New(ctx, fs)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reloaded.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("expected both entries to be recreated on disk after flush, got %v", after)
	}
}

func TestRefreshDetectsNewFiles(t *testing.T) {
	root := t.TempDir()
	fs, err := filesystem.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s1, err := deb822store.New(ctx, fs)
	if err != nil {
		t.Fatal(err)
	}

	// s2 is a second Store instance over the same backend (simulates a second
	// process or a restart without data).
	s2, err := deb822store.New(ctx, fs)
	if err != nil {
		t.Fatal(err)
	}

	// s1 writes and flushes
	if err := s1.UpsertEntry(ctx, entry("curl", "7.88", "arm64")); err != nil {
		t.Fatal(err)
	}
	if err := s1.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	// Before Refresh, s2 is empty.
	before, err := s2.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 0 {
		t.Fatalf("expected 0 entries before Refresh, got %d", len(before))
	}

	// After Refresh, s2 sees the entry.
	if err := s2.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := s2.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].Package != "curl" {
		t.Fatalf("expected curl after Refresh, got %v", after)
	}
}


func TestUpstreamStateRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	metadata.Now = func() time.Time { return now }
	t.Cleanup(func() { metadata.Now = time.Now })

	st := model.UpstreamPackageState{
		Upstream:        "debian-security",
		PackageName:     "openssl",
		Arch:            "amd64",
		UpstreamVersion: "3.0.11",
	}
	if err := s.UpsertUpstreamState(ctx, st); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetUpstreamState(ctx, "debian-security", "openssl", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected state, got nil")
	}
	if got.UpstreamVersion != "3.0.11" {
		t.Fatalf("expected version 3.0.11, got %s", got.UpstreamVersion)
	}
	if !got.LastChecked.Equal(now) {
		t.Fatalf("expected LastChecked %v, got %v", now, got.LastChecked)
	}

	// Unknown lookup returns nil, no error.
	none, err := s.GetUpstreamState(ctx, "debian-security", "openssl", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("expected nil for unknown arch")
	}
}

func TestReset(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if err := s.UpsertEntry(ctx, entry("vim", "9.0", "amd64")); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset(ctx); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after Reset, got %d", len(entries))
	}
}

func TestFirstSeenSetOnInsert(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	metadata.Now = func() time.Time { return now }
	t.Cleanup(func() { metadata.Now = time.Now })

	e := entry("htop", "3.2", "amd64")
	e.FirstSeen = time.Time{} // zero  --  should be filled in
	if err := s.UpsertEntry(ctx, e); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	if !entries[0].FirstSeen.Equal(now) {
		t.Fatalf("expected FirstSeen %v, got %v", now, entries[0].FirstSeen)
	}
}

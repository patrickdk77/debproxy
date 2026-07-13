package valkeystore_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
)

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
	s := newStore(t)
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

// TestListEntriesAcrossBucketBatches is the regression test for the
// chunked-read fix: a bucket with more members than a single SSCAN/MGET
// batch (valkeycache.ScanSetMemberCount / MGetBatchSize) must still list
// every entry correctly, with none dropped or duplicated at a batch
// boundary. Mirrors the equivalent internal/upstream test for the same
// underlying pattern.
func TestListEntriesAcrossBucketBatches(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	const n = 1000 + 250 // spans two SSCAN/MGET batches, second partial
	for i := 0; i < n; i++ {
		if err := s.UpsertEntry(ctx, entry("apt", strconv.Itoa(i)+".0", "amd64")); err != nil {
			t.Fatalf("UpsertEntry %d: %v", i, err)
		}
	}

	entries, err := s.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("ListEntries returned %d entries, want %d", len(entries), n)
	}
	seen := make(map[string]bool, n)
	for _, e := range entries {
		key := e.Package + ":" + e.Version
		if seen[key] {
			t.Fatalf("duplicate entry %s in result", key)
		}
		seen[key] = true
	}
}

func TestUpsertUpdatesExisting(t *testing.T) {
	s := newStore(t)
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
	s := newStore(t)
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
	s := newStore(t)
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

func TestFindEntryEpochVersionSurvivesBucketMemberSplit(t *testing.T) {
	// Debian epoch versions contain a colon (e.g. "2:1.4-1"), which must not
	// be confused with the ":" separator used for bucket SET members.
	s := newStore(t)
	ctx := context.Background()

	e := entry("perl", "2:5.36.0-7", "amd64")
	if err := s.UpsertEntry(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, err := s.FindEntry(ctx, model.Selector{OS: "debian"}, "perl", "2:5.36.0-7")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Version != "2:5.36.0-7" {
		t.Fatalf("expected epoch version preserved, got %v", got)
	}

	entries, err := s.ListEntries(ctx, model.Selector{OS: "debian"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Version != "2:5.36.0-7" {
		t.Fatalf("expected 1 entry with epoch version intact, got %v", entries)
	}
}

func TestSelectorFiltering(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

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

func TestUpstreamStateRoundTrip(t *testing.T) {
	s := newStore(t)
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

	none, err := s.GetUpstreamState(ctx, "debian-security", "openssl", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("expected nil for unknown arch")
	}
}

func TestReset(t *testing.T) {
	s := newStore(t)
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
	s := newStore(t)
	ctx := context.Background()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	metadata.Now = func() time.Time { return now }
	t.Cleanup(func() { metadata.Now = time.Now })

	e := entry("htop", "3.2", "amd64")
	e.FirstSeen = time.Time{} // zero -- should be filled in
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

func TestFlushMigrateRefreshAreNoops(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func TestPing(t *testing.T) {
	s := newStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

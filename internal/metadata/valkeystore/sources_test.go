package valkeystore_test

import (
	"context"
	"testing"

	"github.com/debproxy/debproxy/internal/model"
)

func srcEntry(pkg, version string) model.SourceEntry {
	return model.SourceEntry{
		OS:        "debian",
		Codename:  "trixie",
		Component: "main",
		Package:   pkg,
		Version:   version,
		Upstream:  "debian-main",
		LocalDir:  model.SourceDir("debian", "trixie", "debian-main", "main", pkg),
		Stanza:    "Package: " + pkg + "\nVersion: " + version + "\n",
	}
}

func TestUpsertSourceEntryAndList(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	e := srcEntry("apt", "2.6.1")
	if err := s.UpsertSourceEntry(ctx, e); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListSourceEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "apt" {
		t.Fatalf("expected 1 apt source entry, got %v", entries)
	}
}

func TestRemoveSourceEntry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	kept := srcEntry("wget", "1.21")
	gone := srcEntry("curl", "7.88")
	if err := s.UpsertSourceEntry(ctx, kept); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSourceEntry(ctx, gone); err != nil {
		t.Fatal(err)
	}

	if err := s.RemoveSourceEntry(ctx, gone); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListSourceEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "wget" {
		t.Fatalf("expected only wget source entry to remain, got %v", entries)
	}

	found, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main"}, "curl", "7.88")
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Fatalf("expected curl source entry gone after RemoveSourceEntry, got %v", found)
	}
}

// TestRemoveSourceEntryUnknownIsNoop is the bad-data counterpart to
// TestRemoveSourceEntry -- see the equivalent binary-entry test's doc comment
// for why a no-match remove must succeed silently, not error.
func TestRemoveSourceEntryUnknownIsNoop(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.RemoveSourceEntry(ctx, srcEntry("never-existed", "1.0")); err != nil {
		t.Fatalf("RemoveSourceEntry on unknown entry: %v", err)
	}
}

func TestFindSourceEntry(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	old := srcEntry("bash", "5.1")
	newer := srcEntry("bash", "5.2")
	if err := s.UpsertSourceEntry(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSourceEntry(ctx, newer); err != nil {
		t.Fatal(err)
	}

	got, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian", Codename: "trixie"}, "bash", "")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Version != "5.2" {
		t.Fatalf("expected version 5.2, got %v", got)
	}

	exact, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian"}, "bash", "5.1")
	if err != nil {
		t.Fatal(err)
	}
	if exact == nil || exact.Version != "5.1" {
		t.Fatalf("expected version 5.1, got %v", exact)
	}

	none, err := s.FindSourceEntry(ctx, model.Selector{}, "nosuchpkg", "")
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Fatal("expected nil for unknown package")
	}
}

// TestUpsertSourceEntryKeepsBothUpstreamsAtIdenticalVersion is the
// SourceEntry counterpart of the same-named IndexEntry test: two upstreams
// (e.g. debian-main and debian-security) can each carry a source package at
// the identical version at once, and before Upstream became part of
// SrcEntry's key, the second upstream's UpsertSourceEntry call silently
// overwrote the first's record -- which is exactly what let
// pullThroughSource pair one upstream's base URL with a different
// upstream's Directory/Version metadata (see server.go's own doc comment on
// the fix).
func TestUpsertSourceEntryKeepsBothUpstreamsAtIdenticalVersion(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	a := srcEntry("hello", "1.0")
	a.Upstream = "debian-main"
	a.UpstreamDir = "pool/main/h/hello"
	a.LocalDir = model.SourceDir("debian", "trixie", "debian-main", "main", "hello")

	b := srcEntry("hello", "1.0")
	b.Upstream = "debian-security"
	b.UpstreamDir = "pool/updates/main/h/hello"
	b.LocalDir = model.SourceDir("debian", "trixie", "debian-security", "main", "hello")

	if err := s.UpsertSourceEntry(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSourceEntry(ctx, b); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListSourceEntries(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected both upstreams' source entries to survive, got %d: %v", len(entries), entries)
	}

	gotA, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Upstream: "debian-main"}, "hello", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if gotA == nil || gotA.UpstreamDir != a.UpstreamDir {
		t.Fatalf("expected debian-main's own entry, got %v", gotA)
	}

	gotB, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Upstream: "debian-security"}, "hello", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if gotB == nil || gotB.UpstreamDir != b.UpstreamDir {
		t.Fatalf("expected debian-security's own entry, got %v", gotB)
	}
}

func TestSourceEntrySelectorFiltering(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	e1 := srcEntry("apt", "2.6.1")
	e1.Codename = "trixie"
	e2 := srcEntry("apt", "2.5.0")
	e2.Codename = "bookworm"
	if err := s.UpsertSourceEntry(ctx, e1); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSourceEntry(ctx, e2); err != nil {
		t.Fatal(err)
	}

	trixie, err := s.ListSourceEntries(ctx, model.Selector{OS: "debian", Codename: "trixie"})
	if err != nil {
		t.Fatal(err)
	}
	if len(trixie) != 1 || trixie[0].Version != "2.6.1" {
		t.Fatalf("expected 1 trixie entry at 2.6.1, got %v", trixie)
	}

	all, err := s.ListSourceEntries(ctx, model.Selector{OS: "debian"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 entries across codenames, got %d", len(all))
	}
}

func TestUpsertSourceEntryFilesDownloadedAndFirstSeenAreSticky(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	e := srcEntry("curl", "8.0")
	e.FilesDownloaded = true
	if err := s.UpsertSourceEntry(ctx, e); err != nil {
		t.Fatal(err)
	}
	firstSeen, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian"}, "curl", "8.0")
	if err != nil {
		t.Fatal(err)
	}
	if firstSeen == nil || !firstSeen.FilesDownloaded {
		t.Fatalf("expected FilesDownloaded true on first insert, got %v", firstSeen)
	}

	// A later metadata-only update (FilesDownloaded false) must not clear the
	// prior download, and must not reset FirstSeen.
	update := srcEntry("curl", "8.0")
	update.FilesDownloaded = false
	if err := s.UpsertSourceEntry(ctx, update); err != nil {
		t.Fatal(err)
	}

	got, err := s.FindSourceEntry(ctx, model.Selector{OS: "debian"}, "curl", "8.0")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected entry, got nil")
	}
	if !got.FilesDownloaded {
		t.Fatal("expected FilesDownloaded to remain true after metadata-only update")
	}
	if !got.FirstSeen.Equal(firstSeen.FirstSeen) {
		t.Fatalf("expected FirstSeen unchanged, got %v want %v", got.FirstSeen, firstSeen.FirstSeen)
	}
}

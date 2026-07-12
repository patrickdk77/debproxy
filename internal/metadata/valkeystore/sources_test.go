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

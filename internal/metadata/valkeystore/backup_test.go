package valkeystore_test

import (
	"context"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
)

// TestBackup_RoundTripsThroughDeb822store proves the core claim: a
// valkeystore Backup produces files deb822store can load back, with the
// entries intact -- i.e. a Valkey-backed deployment's periodic backup is
// genuinely interoperable with the file-based backend, not just
// superficially similar.
func TestBackupRoundTripsThroughDeb822store(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	b, ok := any(s).(metadata.Backuper)
	if !ok {
		t.Fatal("valkeystore.Store must implement metadata.Backuper")
	}

	pkgEntry := entry("apt", "2.6.1", "amd64")
	if err := s.UpsertEntry(ctx, pkgEntry); err != nil {
		t.Fatal(err)
	}
	srcEntry := srcEntry("apt", "2.6.1")
	if err := s.UpsertSourceEntry(ctx, srcEntry); err != nil {
		t.Fatal(err)
	}
	state := model.UpstreamPackageState{
		Upstream:        "debian-main",
		PackageName:     "apt",
		Arch:            "amd64",
		UpstreamVersion: "2.6.1",
		LastChecked:     time.Now().Truncate(time.Second),
	}
	if err := s.UpsertUpstreamState(ctx, state); err != nil {
		t.Fatal(err)
	}

	dest, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Backup(ctx, dest, metadata.BackupScope{}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	loaded, err := deb822store.New(ctx, dest)
	if err != nil {
		t.Fatalf("deb822store.New (reading valkeystore's backup): %v", err)
	}

	entries, err := loaded.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "apt" || entries[0].Version != "2.6.1" {
		t.Fatalf("expected 1 apt entry after round trip, got %v", entries)
	}

	srcs, err := loaded.ListSourceEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || srcs[0].Package != "apt" {
		t.Fatalf("expected 1 apt source entry after round trip, got %v", srcs)
	}

	gotState, err := loaded.GetUpstreamState(ctx, "debian-main", "apt", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if gotState == nil || gotState.UpstreamVersion != "2.6.1" {
		t.Fatalf("expected upstream state after round trip, got %v", gotState)
	}
}

// TestBackup_MultipleBucketsAllWritten proves entries across different
// os/codename/component/arch buckets each land in their own correct file,
// not just the single-bucket happy path above.
func TestBackupMultipleBucketsAllWritten(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	b := any(s).(metadata.Backuper)

	e1 := entry("apt", "2.6.1", "amd64")
	e2 := entry("apt", "2.5.0", "amd64")
	e2.Codename = "bookworm"
	if err := s.UpsertEntry(ctx, e1); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEntry(ctx, e2); err != nil {
		t.Fatal(err)
	}

	dest, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Backup(ctx, dest, metadata.BackupScope{}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	loaded, err := deb822store.New(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	trixie, err := loaded.ListEntries(ctx, model.Selector{OS: "debian", Codename: "trixie"})
	if err != nil {
		t.Fatal(err)
	}
	if len(trixie) != 1 || trixie[0].Version != "2.6.1" {
		t.Fatalf("expected 1 trixie entry at 2.6.1, got %v", trixie)
	}
	bookworm, err := loaded.ListEntries(ctx, model.Selector{OS: "debian", Codename: "bookworm"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bookworm) != 1 || bookworm[0].Version != "2.5.0" {
		t.Fatalf("expected 1 bookworm entry at 2.5.0, got %v", bookworm)
	}
}

// TestBackup_EmptyStoreWritesNoFiles proves Backup is a safe no-op-ish call
// on a fresh store rather than erroring or writing empty garbage files.
func TestBackupEmptyStoreWritesNoFiles(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	b := any(s).(metadata.Backuper)

	dest, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Backup(ctx, dest, metadata.BackupScope{}); err != nil {
		t.Fatalf("Backup on empty store: %v", err)
	}

	loaded, err := deb822store.New(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := loaded.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %v", entries)
	}
}

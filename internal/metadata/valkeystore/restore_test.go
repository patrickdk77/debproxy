package valkeystore_test

import (
	"context"
	"testing"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
)

// TestRestoreRoundTripsFromBackup proves the actual recovery path: entries
// and source entries backed up from one Store land correctly in a completely
// different, empty Store via Restore -- i.e. Restore is a real inverse of
// Backup, not just a same-process convenience.
func TestRestoreRoundTripsFromBackup(t *testing.T) {
	ctx := context.Background()

	original := newStore(t)
	b := any(original).(metadata.Backuper)

	pkgEntry := entry("apt", "2.6.1", "amd64")
	if err := original.UpsertEntry(ctx, pkgEntry); err != nil {
		t.Fatal(err)
	}
	srcE := srcEntry("apt", "2.6.1")
	if err := original.UpsertSourceEntry(ctx, srcE); err != nil {
		t.Fatal(err)
	}

	dest, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Backup(ctx, dest, metadata.BackupScope{}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// A completely separate, empty store -- simulating Valkey having lost
	// (or never had) this data.
	fresh := newStore(t)
	packages, sources, err := fresh.Restore(ctx, dest)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if packages != 1 {
		t.Errorf("expected 1 package restored, got %d", packages)
	}
	if sources != 1 {
		t.Errorf("expected 1 source restored, got %d", sources)
	}

	entries, err := fresh.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "apt" || entries[0].Version != "2.6.1" {
		t.Fatalf("expected restored apt entry, got %v", entries)
	}

	srcs, err := fresh.ListSourceEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || srcs[0].Package != "apt" {
		t.Fatalf("expected restored apt source entry, got %v", srcs)
	}
}

// TestRestoreEmptyBackupIsNoop proves Restore against a backup destination
// with nothing in it succeeds cleanly rather than erroring.
func TestRestoreEmptyBackupIsNoop(t *testing.T) {
	ctx := context.Background()
	dest, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	fresh := newStore(t)
	packages, sources, err := fresh.Restore(ctx, dest)
	if err != nil {
		t.Fatalf("Restore on empty backup: %v", err)
	}
	if packages != 0 || sources != 0 {
		t.Errorf("expected 0 packages/sources restored from an empty backup, got packages=%d sources=%d", packages, sources)
	}
}

// TestRestoreDoesNotClobberNewerLocalEntries proves Restore is additive via
// UpsertEntry's own version-comparison semantics -- restoring an older
// backed-up version must not regress a store that already has something
// newer for the same package (e.g. reconciled from the pool after the
// backup was taken, before Restore ran).
func TestRestoreDoesNotClobberNewerLocalEntries(t *testing.T) {
	ctx := context.Background()

	original := newStore(t)
	b := any(original).(metadata.Backuper)
	if err := original.UpsertEntry(ctx, entry("apt", "2.6.1", "amd64")); err != nil {
		t.Fatal(err)
	}
	dest, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Backup(ctx, dest, metadata.BackupScope{}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	fresh := newStore(t)
	// Simulate the fresh store already having a newer version indexed (e.g.
	// from a pool-walk reconciliation that ran before Restore).
	if err := fresh.UpsertEntry(ctx, entry("apt", "2.7.0", "amd64")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := fresh.Restore(ctx, dest); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	found, err := fresh.FindEntry(ctx, model.Selector{OS: "debian", Codename: "trixie", Component: "main", Arch: "amd64"}, "apt", "")
	if err != nil {
		t.Fatal(err)
	}
	if found == nil || found.Version != "2.7.0" {
		t.Fatalf("expected the newer 2.7.0 entry to survive Restore, got %v", found)
	}
}

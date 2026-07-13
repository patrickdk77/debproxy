package syncer_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/syncer"
)

func newFilesystemSyncer(t *testing.T) (*syncer.Syncer, *filesystem.Store) {
	t.Helper()
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	s := syncer.New(&config.Config{}, store, nil, nil, nil, nil, nil)
	return s, store
}

func TestCurrentSnapshotName_NoneYet(t *testing.T) {
	s, _ := newFilesystemSyncer(t)
	_, err := s.CurrentSnapshotName(context.Background())
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist error, got %v", err)
	}
}

func TestCurrentSnapshotAge_NoneYet(t *testing.T) {
	s, _ := newFilesystemSyncer(t)
	_, ok, err := s.CurrentSnapshotAge(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when no snapshot has ever been published")
	}
}

func TestCurrentSnapshotName_AfterWrite(t *testing.T) {
	s, store := newFilesystemSyncer(t)
	ctx := context.Background()
	const id = "2026-07-08T12-00-00"
	if err := store.WriteFile(ctx, "current/snapshot-name", strings.NewReader(id), int64(len(id))); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	name, err := s.CurrentSnapshotName(ctx)
	if err != nil {
		t.Fatalf("CurrentSnapshotName: %v", err)
	}
	if name != id {
		t.Fatalf("got %q, want %q", name, id)
	}
}

func TestCurrentSnapshotAge_AfterWrite(t *testing.T) {
	s, store := newFilesystemSyncer(t)
	ctx := context.Background()
	const id = "2026-07-08T12-00-00"
	if err := store.WriteFile(ctx, "current/snapshot-name", strings.NewReader(id), int64(len(id))); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	published, err := time.Parse(syncer.SnapshotIDFormat, id)
	if err != nil {
		t.Fatalf("parse reference time: %v", err)
	}
	now := published.Add(10 * time.Minute)

	age, ok, err := s.CurrentSnapshotAge(ctx, now)
	if err != nil {
		t.Fatalf("CurrentSnapshotAge: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if age != 10*time.Minute {
		t.Fatalf("got age %v, want %v", age, 10*time.Minute)
	}
}

func TestCurrentSnapshotAge_MalformedName(t *testing.T) {
	s, store := newFilesystemSyncer(t)
	ctx := context.Background()
	const bogus = "not-a-timestamp"
	if err := store.WriteFile(ctx, "current/snapshot-name", strings.NewReader(bogus), int64(len(bogus))); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, err := s.CurrentSnapshotAge(ctx, time.Now())
	if err == nil {
		t.Fatal("expected an error for a malformed snapshot id")
	}
}

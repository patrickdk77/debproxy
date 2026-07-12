package metadata

import (
	"context"
	"errors"
	"time"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

var ErrNotImplemented = errors.New("metadata backend not implemented")

// MetadataIndex is the persistent package and upstream-state index.
// It is the authoritative record of what is in the pool and must survive restarts.
type MetadataIndex interface {
	Ping(ctx context.Context) error
	Migrate(ctx context.Context) error
	Reset(ctx context.Context) error
	// Refresh reloads any persisted index files that have been written since the
	// last load, and evicts entries for files that no longer exist. No-op for
	// backends that keep their own authoritative state (e.g. MySQL).
	Refresh(ctx context.Context) error
	// Flush writes all dirty in-memory state to the backing store. No-op for
	// backends that write through on every mutation.
	Flush(ctx context.Context) error

	// UpsertEntry inserts or updates a package placement.
	UpsertEntry(ctx context.Context, entry model.IndexEntry) error
	// ListEntries returns entries matching the selector (empty fields match any).
	ListEntries(ctx context.Context, sel model.Selector) ([]model.IndexEntry, error)
	// EntryByDigest returns any entry for the given content digest (dedup lookup).
	EntryByDigest(ctx context.Context, digest model.Digest) (*model.IndexEntry, error)
	// FindEntry returns the matching entry; if version is empty, the highest
	// version within the selector is returned. Returns nil if not found.
	FindEntry(ctx context.Context, sel model.Selector, pkg, version string) (*model.IndexEntry, error)

	UpsertUpstreamState(ctx context.Context, state model.UpstreamPackageState) error
	GetUpstreamState(ctx context.Context, upstream, name, arch string) (*model.UpstreamPackageState, error)

	// UpsertSourceEntry inserts or updates a source package record.
	UpsertSourceEntry(ctx context.Context, entry model.SourceEntry) error
	// ListSourceEntries returns source entries matching the selector (empty fields match any).
	// Arch is ignored for source entries since sources are architecture-independent.
	ListSourceEntries(ctx context.Context, sel model.Selector) ([]model.SourceEntry, error)
	// FindSourceEntry returns the matching source entry; if version is empty, the highest
	// version within the selector is returned. Returns nil if not found.
	FindSourceEntry(ctx context.Context, sel model.Selector, pkg, version string) (*model.SourceEntry, error)
}

// BackupScope narrows a Backuper.Backup call to a subset of the index -- the
// zero value means "everything". OS/Codename/Component scope package and
// source entries to one layout, one component at a time (a Backup caller
// iterating layouts and components independently, as cmd/debproxy's
// per-layout refresh loop does, uses this to pull and write only that one
// slice at a time). Upstreams (upstream names) separately scopes
// upstream-fetch state, since it isn't itself partitioned by component.
type BackupScope struct {
	OS        string
	Codename  string
	Component string
	Upstreams []string
}

// Backuper is an optional capability implemented by MetadataIndex backends
// that have no file-based durability of their own (e.g. valkeystore, which
// lives entirely in Valkey) and so support writing a snapshot of the current
// index (or, per scope, a subset of it) out to a storage.Storage backend on
// demand -- in the same file layout deb822store itself uses, so the result is
// readable by either backend. Backends that already persist to a storage
// backend incrementally (e.g. deb822store, via Flush) don't need to
// implement this; callers should type-assert for it rather than requiring it
// on every MetadataIndex.
type Backuper interface {
	Backup(ctx context.Context, dest storage.Storage, scope BackupScope) error
}

// Now returns the current time (overridable in tests).
var Now = time.Now

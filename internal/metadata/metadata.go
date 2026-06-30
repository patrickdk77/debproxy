package metadata

import (
	"context"
	"errors"
	"time"

	"github.com/debproxy/debproxy/internal/model"
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
}

// Now returns the current time (overridable in tests).
var Now = time.Now

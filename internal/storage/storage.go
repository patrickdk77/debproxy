package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/debproxy/debproxy/internal/model"
)

var ErrNotImplemented = errors.New("storage backend not implemented")

// ErrAccessDenied indicates a backend refused an operation for permission
// reasons (e.g. an S3 403 on a write, list, or bucket operation). Callers can
// match it with errors.Is to distinguish a permissions failure from a missing
// object (fs.ErrNotExist) or a transient error. Not-found is deliberately kept
// separate: backends report a missing object as fs.ErrNotExist so os.IsNotExist
// works uniformly.
var ErrAccessDenied = errors.New("access denied")

// CleanRelPath cleans a caller-supplied relative path and rejects any attempt
// to escape upward (a leading ".." remaining after cleaning) via ".."
// segments. A leading "/" is stripped rather than rejected, so callers get a
// normalized relative path either way. Both storage backends (filesystem and
// S3) call this before joining the result to their own root, so a
// client/upstream-controlled path can never resolve outside of it -- neither
// backend should reimplement this check independently.
func CleanRelPath(p string) (string, error) {
	if strings.IndexByte(p, 0) >= 0 {
		// A NUL cannot appear in any real path. The OS rejects it, and an
		// object store accepts it, so letting it through produces a key
		// nothing can read back.
		return "", fmt.Errorf("invalid path %q: contains NUL", p)
	}
	// TrimLeft rather than TrimPrefix: "//x" must become "x", not "/x".
	// A surviving leading slash is not traversal, but it is a path that
	// no longer sits under the root it was meant to.
	trimmed := strings.TrimLeft(strings.TrimSpace(p), "/")
	clean := path.Clean(trimmed)
	if clean == "." {
		clean = ""
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("invalid path %q", p)
	}
	return clean, nil
}

// FileInfo describes a stored file.
type FileInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
}

// FileStore stores pool files by path.
type FileStore interface {
	PutFile(ctx context.Context, poolPath string, r io.Reader, size int64) error
	Open(ctx context.Context, poolPath string) (io.ReadCloser, error)
	Stat(ctx context.Context, poolPath string) (FileInfo, error)
	Exists(ctx context.Context, poolPath string) (bool, error)
	Delete(ctx context.Context, poolPath string) error
	ComputeChecksums(ctx context.Context, poolPath string) (model.Checksums, error)
	// WalkPool visits every pool file, passing its FileInfo (size, mod time)
	// straight from the underlying listing (filesystem: fs.DirEntry.Info();
	// S3: the ListObjectsV2 page) so callers that need that metadata don't
	// have to issue a separate Stat per file.
	WalkPool(ctx context.Context, fn func(info FileInfo) error) error
	// CleanupTempFiles removes incomplete upload artifacts older than
	// olderThan and returns how many were removed. PutFile writes through a
	// temp file that's renamed into place on success (see the filesystem
	// backend); if the process is killed mid-write (crash, OOM, forced
	// restart) rather than failing normally, the deferred cleanup that
	// removes that temp file never runs, leaking it forever -- this is that
	// cleanup's backstop. A no-op for backends with no such on-disk artifact
	// of their own (e.g. S3, whose PutObject is a single atomic call with no
	// exposed temp state for us to manage).
	CleanupTempFiles(ctx context.Context, olderThan time.Time) (int, error)
}

// Publisher manages write-once published dists trees and snapshot aliases.
type Publisher interface {
	WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error
	DeletePublished(ctx context.Context, relPath string) error
	OpenPublished(ctx context.Context, relPath string) (io.ReadCloser, error)
	StatPublished(ctx context.Context, relPath string) (FileInfo, error)
	ListPublished(ctx context.Context, prefix string) ([]string, error)
	// ListPublishedInfo is the FileInfo-returning analog of ListPublished, for
	// callers that need mod times without a separate StatPublished per file.
	ListPublishedInfo(ctx context.Context, prefix string) ([]FileInfo, error)
	ListSnapshots(ctx context.Context, osName string) ([]SnapshotRef, error)
	ResolveSnapshot(ctx context.Context, osName string, at time.Time) (string, error)
}

// SnapshotRef identifies a published snapshot.
type SnapshotRef struct {
	ID        string
	OS        string
	CreatedAt time.Time
}

// Storage combines pool file storage and snapshot publishing.
type Storage interface {
	FileStore
	Publisher
	Ping(ctx context.Context) error
}

// PoolRouter is an optional capability for backends that can publish
// prefix-rewrite rules mapping a published base's pool path back to the
// shared pool.
//
// It exists because apt resolves a Packages stanza's Filename relative
// to the sources.list URIs base, while debproxy publishes each
// snapshot's metadata under its own prefix and keeps one shared pool.
// Requests through debproxy are rewritten by the router; requests made
// straight to the backend are not, so without this every .deb 404s for
// a client pointed directly at the bucket even though the metadata
// resolves fine.
//
// Backends that need no rewrite -- the filesystem tree, where a single
// symlink does the same job -- simply do not implement it, and callers
// skip the step via a type assertion rather than branching on backend
// type.
type PoolRouter interface {
	// SyncPoolRoutes reconciles the backend's rewrite rules so every
	// base in bases resolves pool files. bases are publish bases with
	// no trailing slash, e.g. "current/debian" or "2026-08-11/debian".
	// The full set is passed every time: implementations reconcile
	// rather than diff, so pruned snapshots lose their rules without a
	// separate delete path.
	SyncPoolRoutes(ctx context.Context, bases []string) error
}

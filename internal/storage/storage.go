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

// CleanRelPath cleans a caller-supplied relative path and rejects any attempt
// to escape upward (a leading ".." remaining after cleaning) via ".."
// segments. A leading "/" is stripped rather than rejected, so callers get a
// normalized relative path either way. Both storage backends (filesystem and
// S3) call this before joining the result to their own root, so a
// client/upstream-controlled path can never resolve outside of it -- neither
// backend should reimplement this check independently.
func CleanRelPath(p string) (string, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(p), "/")
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

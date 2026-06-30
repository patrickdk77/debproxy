package storage

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/debproxy/debproxy/internal/model"
)

var ErrNotImplemented = errors.New("storage backend not implemented")

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
	WalkPool(ctx context.Context, fn func(poolPath string) error) error
}

// Publisher manages write-once published dists trees and snapshot aliases.
type Publisher interface {
	WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error
	DeletePublished(ctx context.Context, relPath string) error
	OpenPublished(ctx context.Context, relPath string) (io.ReadCloser, error)
	StatPublished(ctx context.Context, relPath string) (FileInfo, error)
	ListPublished(ctx context.Context, prefix string) ([]string, error)
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

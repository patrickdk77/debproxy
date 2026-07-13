package storagefactory

import (
	"fmt"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/filecache"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/storage/s3store"
)

// New creates a storage backend from configuration, layering the optional
// filecache.Store LRU cache over it when storage.file_cache.size is set to
// a positive size (filecache.Wrap is a no-op otherwise).
func New(cfg *config.Config) (storage.Storage, error) {
	var store storage.Storage
	var err error
	switch cfg.Storage.Backend {
	case config.BackendFilesystem:
		store, err = filesystem.New(cfg.Storage.Filesystem.Root)
	case config.BackendS3:
		store, err = s3store.New(cfg.Storage.S3)
	default:
		return nil, fmt.Errorf("unknown storage backend %q", cfg.Storage.Backend)
	}
	if err != nil {
		return nil, err
	}
	maxBytes, err := config.ParseSize(cfg.Storage.FileCache.Size)
	if err != nil {
		return nil, fmt.Errorf("storage.file_cache.size: %w", err)
	}
	return filecache.Wrap(store, maxBytes), nil
}

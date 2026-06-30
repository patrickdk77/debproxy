package storagefactory

import (
	"fmt"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/storage/s3store"
)

// New creates a storage backend from configuration.
func New(cfg *config.Config) (storage.Storage, error) {
	switch cfg.Storage.Backend {
	case config.BackendFilesystem:
		return filesystem.New(cfg.Storage.Filesystem.Root)
	case config.BackendS3:
		return s3store.New(cfg.Storage.S3)
	default:
		return nil, fmt.Errorf("unknown storage backend %q", cfg.Storage.Backend)
	}
}

package metadatafactory

import (
	"context"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/storage"
)

// New creates a metadata index backed by deb822+zstd files in the storage backend.
func New(ctx context.Context, store storage.Storage) (metadata.MetadataIndex, error) {
	return deb822store.New(ctx, store)
}

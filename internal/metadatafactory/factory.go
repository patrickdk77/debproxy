package metadatafactory

import (
	"context"
	"fmt"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/metadata/valkeystore"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// New creates a metadata index. When cfg.Valkey.Enabled is set, the index is
// backed by a shared Valkey deployment (valkeystore) so it can be shared
// across debproxy replicas; otherwise it falls back to the existing
// deb822+zstd files held in memory and persisted through the storage backend
// (deb822store). Migrating an existing deb822store install to Valkey needs
// no separate import step: `debproxy rebuild` already repopulates whichever
// MetadataIndex it's given by walking the pool, so running it once against
// the new backend is the whole migration.
func New(ctx context.Context, store storage.Storage, cfg *config.Config) (metadata.MetadataIndex, error) {
	if cfg.Valkey.Enabled {
		client, err := valkeycache.NewClient(cfg.Valkey.URL)
		if err != nil {
			return nil, fmt.Errorf("connect to valkey: %w", err)
		}
		return valkeystore.New(client, cfg.Valkey.KeyPrefix), nil
	}
	return deb822store.New(ctx, store)
}

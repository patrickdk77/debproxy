// Package valkeystore implements metadata.MetadataIndex against a shared
// Valkey/Redis deployment, so the pool metadata index (what debproxy has
// actually pool-cached) is shared across replicas instead of held fully
// resident in each process's memory the way deb822store.Store holds it.
//
// Every mutating method writes straight to Valkey, so Migrate/Flush/Refresh
// are no-ops -- there is no local cache to reconcile against a backing file,
// matching the MetadataIndex interface doc comments' expectation for
// backends that write through on every mutation and keep their own
// authoritative state.
package valkeystore

import (
	"context"
	"fmt"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// Store is a MetadataIndex backed by Valkey.
type Store struct {
	v    valkey.Client
	keys valkeycache.Keys
}

var _ metadata.MetadataIndex = (*Store)(nil)

// New creates a Store using v for storage. prefix is prepended to every key
// (see valkeycache.Keys); pass "" for no prefix.
func New(v valkey.Client, prefix string) *Store {
	return &Store{v: v, keys: valkeycache.Keys{Prefix: prefix}}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.v.Do(ctx, s.v.B().Ping().Build()).Error()
}

// Migrate is a no-op: there is no schema to create ahead of time, since
// every key is written on first use.
func (s *Store) Migrate(context.Context) error { return nil }

// Refresh is a no-op: Valkey is the authoritative store itself, not a cache
// of some other backing file that could have changed underneath it.
func (s *Store) Refresh(context.Context) error { return nil }

// Flush is a no-op: every mutating method below already writes through to
// Valkey immediately.
func (s *Store) Flush(context.Context) error { return nil }

// Reset deletes every key under this Store's prefix. Used by `debproxy
// rebuild --reset` and by tests; not part of any hot path. Cluster-safe: it
// enumerates every node via v.Nodes() and SCANs each one, since SCAN is not
// a keyed command and so is not automatically routed in cluster mode.
func (s *Store) Reset(ctx context.Context) error {
	pattern := s.keys.Prefix + "*"
	for _, node := range s.v.Nodes() {
		if err := scanDelete(ctx, node, pattern); err != nil {
			return fmt.Errorf("reset: %w", err)
		}
	}
	return nil
}

func scanDelete(ctx context.Context, v valkey.Client, pattern string) error {
	var cursor uint64
	for {
		entry, err := v.Do(ctx, v.B().Scan().Cursor(cursor).Match(pattern).Count(1000).Build()).AsScanEntry()
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		if len(entry.Elements) > 0 {
			if err := v.Do(ctx, v.B().Del().Key(entry.Elements...).Build()).Error(); err != nil {
				return fmt.Errorf("del: %w", err)
			}
		}
		cursor = entry.Cursor
		if cursor == 0 {
			return nil
		}
	}
}

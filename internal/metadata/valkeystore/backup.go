package valkeystore

import (
	"bytes"
	"context"
	"fmt"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

var _ metadata.Backuper = (*Store)(nil)

// Backup pulls the current package, source, and upstream-state entries
// matching scope out of Valkey and writes them to dest using deb822store's
// exact file layout and compressed format (metadata/index/{os}/{codename}/{component}/{arch}.packages.zst,
// metadata/index/{os}/{codename}/{component}/sources.zst,
// metadata/upstream/{upstream}.state.zst). This gives a Valkey-backed
// deployment a storage-durable snapshot of its metadata index -- unlike
// Flush (a no-op here, since every mutation already writes through to Valkey
// immediately), Backup always re-reads and re-writes everything matching
// scope, since there's no "dirty" subset to track. A zero-value scope backs
// up the entire index; cmd/debproxy's per-layout refresh loop instead scopes
// each call to one layout's single component at a time (see
// saveLayoutMetadata), so a single call never pulls more than one
// (layout, component)'s worth of data into memory at once.
func (s *Store) Backup(ctx context.Context, dest storage.Storage, scope metadata.BackupScope) error {
	if err := s.backupEntries(ctx, dest, scope); err != nil {
		return fmt.Errorf("backup pool entries: %w", err)
	}
	if err := s.backupSources(ctx, dest, scope); err != nil {
		return fmt.Errorf("backup source entries: %w", err)
	}
	if err := s.backupUpstreamStates(ctx, dest, scope); err != nil {
		return fmt.Errorf("backup upstream states: %w", err)
	}
	return nil
}

type indexBucketKey struct{ os, codename, component, arch string }

func (s *Store) backupEntries(ctx context.Context, dest storage.Storage, scope metadata.BackupScope) error {
	entries, err := s.ListEntries(ctx, model.Selector{OS: scope.OS, Codename: scope.Codename, Component: scope.Component})
	if err != nil {
		return err
	}
	grouped := make(map[indexBucketKey][]model.IndexEntry, len(entries))
	for _, e := range entries {
		k := indexBucketKey{e.OS, e.Codename, e.Component, e.Arch}
		grouped[k] = append(grouped[k], e)
	}
	for k, group := range grouped {
		data, err := deb822store.SerializeEntries(group)
		if err != nil {
			return fmt.Errorf("serialize %s/%s/%s/%s: %w", k.os, k.codename, k.component, k.arch, err)
		}
		relPath := deb822store.IndexRelPath(k.os, k.codename, k.component, k.arch)
		if err := dest.WriteFile(ctx, relPath, bytes.NewReader(data), int64(len(data))); err != nil {
			return fmt.Errorf("write %s: %w", relPath, err)
		}
	}
	return nil
}

type sourceBucketKey struct{ os, codename, component string }

func (s *Store) backupSources(ctx context.Context, dest storage.Storage, scope metadata.BackupScope) error {
	srcs, err := s.ListSourceEntries(ctx, model.Selector{OS: scope.OS, Codename: scope.Codename, Component: scope.Component})
	if err != nil {
		return err
	}
	grouped := make(map[sourceBucketKey][]model.SourceEntry, len(srcs))
	for _, e := range srcs {
		k := sourceBucketKey{e.OS, e.Codename, e.Component}
		grouped[k] = append(grouped[k], e)
	}
	for k, group := range grouped {
		data, err := deb822store.SerializeSources(group)
		if err != nil {
			return fmt.Errorf("serialize %s/%s/%s sources: %w", k.os, k.codename, k.component, err)
		}
		relPath := deb822store.SourceRelPath(k.os, k.codename, k.component)
		if err := dest.WriteFile(ctx, relPath, bytes.NewReader(data), int64(len(data))); err != nil {
			return fmt.Errorf("write %s: %w", relPath, err)
		}
	}
	return nil
}

func (s *Store) backupUpstreamStates(ctx context.Context, dest storage.Storage, scope metadata.BackupScope) error {
	states, err := s.ListUpstreamStates(ctx, scope.Upstreams)
	if err != nil {
		return err
	}
	grouped := make(map[string][]model.UpstreamPackageState, len(states))
	for _, st := range states {
		grouped[st.Upstream] = append(grouped[st.Upstream], st)
	}
	for upstream, group := range grouped {
		data, err := deb822store.SerializeStates(group)
		if err != nil {
			return fmt.Errorf("serialize %s upstream state: %w", upstream, err)
		}
		relPath := deb822store.StateRelPath(upstream)
		if err := dest.WriteFile(ctx, relPath, bytes.NewReader(data), int64(len(data))); err != nil {
			return fmt.Errorf("write %s: %w", relPath, err)
		}
	}
	return nil
}

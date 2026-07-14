package valkeystore

import (
	"context"
	"fmt"

	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

// Restore repopulates this Store from metadata files previously written by
// Backup, reading them via a temporary deb822store.Store pointed at src (the
// same storage.Storage the live process already uses) -- deb822store.New
// loads that exact file layout natively, so no separate deserialization code
// is needed here. Returns the number of package and source entries restored.
//
// Intended for the startup reconciliation path: if Valkey's own copy of the
// index is found empty (lost, wiped, or never populated) when the process
// starts, this recovers whatever was last durably backed up (at most
// schedule.metadata_flush stale) before the pool-walk reconciliation
// (rebuild.Run, called with ResetIndex: false) picks up anything newer than
// that backup. Upstream-fetch state (UpstreamPackageState) is deliberately
// not restored here: deb822store exposes no bulk enumeration of it (only a
// per-package point lookup, matching the shared MetadataIndex interface),
// and losing it only costs auto_update a redundant re-check of packages it
// already has -- not data loss, unlike the package/source index this
// protects pool files and snapshot generation with.
func (s *Store) Restore(ctx context.Context, src storage.Storage) (packages, sources int, err error) {
	backup, err := deb822store.New(ctx, src)
	if err != nil {
		return 0, 0, fmt.Errorf("load backup: %w", err)
	}

	entries, err := backup.ListEntries(ctx, model.Selector{})
	if err != nil {
		return 0, 0, fmt.Errorf("list backed-up entries: %w", err)
	}
	for _, e := range entries {
		if err := s.UpsertEntry(ctx, e); err != nil {
			return packages, sources, fmt.Errorf("restore entry %s %s: %w", e.Package, e.Version, err)
		}
		packages++
	}

	srcs, err := backup.ListSourceEntries(ctx, model.Selector{})
	if err != nil {
		return packages, sources, fmt.Errorf("list backed-up source entries: %w", err)
	}
	for _, e := range srcs {
		if err := s.UpsertSourceEntry(ctx, e); err != nil {
			return packages, sources, fmt.Errorf("restore source entry %s %s: %w", e.Package, e.Version, err)
		}
		sources++
	}
	return packages, sources, nil
}

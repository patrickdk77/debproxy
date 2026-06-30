package syncer

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/debproxy/debproxy/internal/model"
)

// Cleanup prunes old snapshots and then removes orphaned pool files.
//
// A snapshot is eligible for deletion when BOTH conditions hold:
//   - the total number of snapshots exceeds maxSnapshots (0 = no count limit)
//   - the snapshot is older than maxSnapshotAge            (0 = no age limit)
//
// After pruning, pool files not referenced by any remaining snapshot or the
// current metadata index are deleted.
func (s *Syncer) Cleanup(ctx context.Context, maxSnapshots int, maxSnapshotAge time.Duration, now time.Time) error {
	deleted, err := s.pruneSnapshots(ctx, maxSnapshots, maxSnapshotAge, now)
	if err != nil {
		return err
	}
	slog.Info("cleanup: snapshots pruned", "deleted", deleted)

	gcDeleted, err := s.gcPool(ctx)
	if err != nil {
		return err
	}
	slog.Info("cleanup: pool GC complete", "orphaned_files_deleted", gcDeleted)

	srcDeleted, err := s.gcSrc(ctx)
	if err != nil {
		return err
	}
	slog.Info("cleanup: src GC complete", "orphaned_files_deleted", srcDeleted)
	return nil
}

func (s *Syncer) pruneSnapshots(ctx context.Context, maxSnapshots int, maxSnapshotAge time.Duration, now time.Time) (int, error) {
	// Both limits must be set; if either is zero no pruning occurs.
	if maxSnapshots == 0 || maxSnapshotAge == 0 {
		return 0, nil
	}

	// Collect all unique snapshot IDs across every configured OS.
	seen := map[string]time.Time{}
	for _, osName := range s.osNames() {
		refs, err := s.store.ListSnapshots(ctx, osName)
		if err != nil {
			return 0, fmt.Errorf("list snapshots for %s: %w", osName, err)
		}
		for _, ref := range refs {
			if _, exists := seen[ref.ID]; !exists {
				seen[ref.ID] = ref.CreatedAt
			}
		}
	}

	type snap struct {
		id string
		t  time.Time
	}
	snaps := make([]snap, 0, len(seen))
	for id, t := range seen {
		snaps = append(snaps, snap{id, t})
	}
	// Newest first so index 0 is the most recent.
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].t.After(snaps[j].t) })

	var toDelete []string
	for i, sn := range snaps {
		if i >= maxSnapshots && now.Sub(sn.t) > maxSnapshotAge {
			toDelete = append(toDelete, sn.id)
		}
	}

	for _, id := range toDelete {
		if err := s.deleteSnapshotTree(ctx, id); err != nil {
			slog.Warn("cleanup: delete snapshot failed", "id", id, "err", err)
		} else {
			slog.Info("cleanup: deleted snapshot", "id", id)
		}
	}
	return len(toDelete), nil
}

// deleteSnapshotTree removes every published file under snapshotID/.
func (s *Syncer) deleteSnapshotTree(ctx context.Context, snapshotID string) error {
	files, err := s.store.ListPublished(ctx, snapshotID)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := s.store.DeletePublished(ctx, f); err != nil {
			slog.Warn("cleanup: delete published file", "path", f, "err", err)
		}
	}
	return nil
}

// gcPool removes pool files not referenced by any remaining snapshot or the
// metadata index, and returns the number of files deleted.
func (s *Syncer) gcPool(ctx context.Context) (int, error) {
	ref, err := s.buildPoolRefSet(ctx)
	if err != nil {
		return 0, err
	}

	var toDelete []string
	if err := s.store.WalkPool(ctx, func(poolPath string) error {
		if !ref[poolPath] {
			toDelete = append(toDelete, poolPath)
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("walk pool: %w", err)
	}

	for _, p := range toDelete {
		if err := s.store.Delete(ctx, p); err != nil {
			slog.Warn("cleanup: delete orphaned file failed", "path", p, "err", err)
		} else {
			slog.Debug("cleanup: deleted orphaned pool file", "path", p)
		}
	}
	return len(toDelete), nil
}

// buildPoolRefSet returns the set of all pool Filename: paths that must be kept.
// It combines two sources:
//  1. Packages index files from every remaining snapshot and the current/ tree.
//  2. PoolPath fields from the in-memory metadata index (belt-and-suspenders for
//     packages downloaded since the last snapshot).
func (s *Syncer) buildPoolRefSet(ctx context.Context) (map[string]bool, error) {
	ref := map[string]bool{}

	// Gather prefixes to scan: current/ plus every remaining snapshot ID.
	prefixes := []string{"current"}
	seenSnap := map[string]bool{}
	for _, osName := range s.osNames() {
		snapRefs, err := s.store.ListSnapshots(ctx, osName)
		if err != nil {
			return nil, fmt.Errorf("list snapshots for %s: %w", osName, err)
		}
		for _, sr := range snapRefs {
			if !seenSnap[sr.ID] {
				seenSnap[sr.ID] = true
				prefixes = append(prefixes, sr.ID)
			}
		}
	}

	for _, prefix := range prefixes {
		files, err := s.store.ListPublished(ctx, prefix)
		if err != nil {
			slog.Warn("cleanup: list published files", "prefix", prefix, "err", err)
			continue
		}
		for _, f := range files {
			if !isUncompressedPackages(f) {
				continue
			}
			if err := s.scanPackagesRefs(ctx, f, ref); err != nil {
				slog.Warn("cleanup: scan Packages file", "path", f, "err", err)
			}
		}
	}

	// Also include every PoolPath known to the metadata index.
	entries, err := s.index.ListEntries(ctx, model.Selector{})
	if err != nil {
		return nil, fmt.Errorf("list metadata entries: %w", err)
	}
	for _, e := range entries {
		ref[e.PoolPath] = true
	}

	return ref, nil
}

// isUncompressedPackages reports whether relPath is a plain (non-compressed)
// binary Packages index file from a dists/ tree.
func isUncompressedPackages(relPath string) bool {
	return relPath[strings.LastIndexByte(relPath, '/')+1:] == "Packages"
}

// scanPackagesRefs opens a Packages file and records every Filename: value.
func (s *Syncer) scanPackagesRefs(ctx context.Context, relPath string, ref map[string]bool) error {
	rc, err := s.store.OpenPublished(ctx, relPath)
	if err != nil {
		return err
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB — handles long Depends: lines
	for sc.Scan() {
		if fn, ok := strings.CutPrefix(sc.Text(), "Filename: "); ok {
			ref[fn] = true
		}
	}
	return sc.Err()
}

// gcSrc removes src/ files not referenced by any remaining snapshot or the
// metadata source index, and returns the number of files deleted.
func (s *Syncer) gcSrc(ctx context.Context) (int, error) {
	ref, err := s.buildSrcRefSet(ctx)
	if err != nil {
		return 0, err
	}

	// src/ files are stored via FileStore (PutFile), so list them via
	// ListPublished which walks the same storage root.
	allSrc, err := s.store.ListPublished(ctx, "src")
	if err != nil {
		return 0, fmt.Errorf("list src files: %w", err)
	}

	var toDelete []string
	for _, p := range allSrc {
		if !ref[p] {
			toDelete = append(toDelete, p)
		}
	}
	for _, p := range toDelete {
		if err := s.store.Delete(ctx, p); err != nil {
			slog.Warn("cleanup: delete orphaned src file failed", "path", p, "err", err)
		} else {
			slog.Debug("cleanup: deleted orphaned src file", "path", p)
		}
	}
	return len(toDelete), nil
}

// buildSrcRefSet returns the set of src/ paths that must be kept.
// It combines file paths from snapshot Sources indices and the metadata source index.
func (s *Syncer) buildSrcRefSet(ctx context.Context) (map[string]bool, error) {
	ref := map[string]bool{}

	// Scan Sources index files from every remaining snapshot and current/.
	prefixes := []string{"current"}
	seenSnap := map[string]bool{}
	for _, osName := range s.osNames() {
		snapRefs, err := s.store.ListSnapshots(ctx, osName)
		if err != nil {
			return nil, fmt.Errorf("list snapshots for %s: %w", osName, err)
		}
		for _, sr := range snapRefs {
			if !seenSnap[sr.ID] {
				seenSnap[sr.ID] = true
				prefixes = append(prefixes, sr.ID)
			}
		}
	}

	for _, prefix := range prefixes {
		files, err := s.store.ListPublished(ctx, prefix)
		if err != nil {
			slog.Warn("cleanup: list published files for src GC", "prefix", prefix, "err", err)
			continue
		}
		for _, f := range files {
			if !isUncompressedSources(f) {
				continue
			}
			if err := s.scanSourcesRefs(ctx, f, ref); err != nil {
				slog.Warn("cleanup: scan Sources file", "path", f, "err", err)
			}
		}
	}

	// Also include all src paths known to the metadata source index.
	srcEntries, err := s.index.ListSourceEntries(ctx, model.Selector{})
	if err != nil {
		return nil, fmt.Errorf("list source entries: %w", err)
	}
	for _, e := range srcEntries {
		for _, f := range e.Files {
			ref[e.LocalDir+"/"+f.Filename] = true
		}
	}

	return ref, nil
}

// isUncompressedSources reports whether relPath is a plain (non-compressed)
// Sources index file from a dists/.../source/ tree.
func isUncompressedSources(relPath string) bool {
	return strings.HasSuffix(relPath, "/source/Sources")
}

// scanSourcesRefs opens a Sources index file and records every file path
// (Directory: + filename from Files:/Checksums sections) into ref.
func (s *Syncer) scanSourcesRefs(ctx context.Context, relPath string, ref map[string]bool) error {
	rc, err := s.store.OpenPublished(ctx, relPath)
	if err != nil {
		return err
	}
	defer rc.Close()

	var dir string
	var filenames []string
	inFiles := false

	flush := func() {
		if dir != "" {
			for _, fn := range filenames {
				ref[dir+"/"+fn] = true
			}
		}
		dir = ""
		filenames = nil
		inFiles = false
	}

	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if d, ok := strings.CutPrefix(line, "Directory: "); ok {
			dir = d
			inFiles = false
			continue
		}
		// Files:, Checksums-Sha256:, Checksums-Sha1: all list " hash size filename"
		if strings.HasPrefix(line, "Files:") ||
			strings.HasPrefix(line, "Checksums-Sha256:") ||
			strings.HasPrefix(line, "Checksums-Sha1:") {
			inFiles = true
			continue
		}
		if inFiles && len(line) > 0 && line[0] == ' ' {
			// " <hash> <size> <filename>"
			if parts := strings.Fields(line); len(parts) == 3 {
				filenames = append(filenames, parts[2])
			}
			continue
		}
		inFiles = false
	}
	flush() // handle final stanza with no trailing blank line
	return sc.Err()
}

// osNames returns the sorted distinct OS names from the resolved layouts.
func (s *Syncer) osNames() []string {
	seen := map[string]bool{}
	for _, l := range s.cfg.ResolvedLayouts {
		seen[l.OS] = true
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

package syncer

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

// Cleanup prunes old snapshots and then removes orphaned pool files.
//
// A snapshot is eligible for deletion based on whichever limits are set:
//   - if both maxSnapshots and maxSnapshotAge are set, BOTH must hold
//   - if only one is set (the other is 0), pruning is based on that one alone
//   - if both are 0, no pruning occurs (both axes are unconstrained)
//
// After pruning, pool files not referenced by any remaining snapshot or the
// current metadata index are deleted.
func (s *Syncer) Cleanup(ctx context.Context, maxSnapshots int, maxSnapshotAge time.Duration, now time.Time) error {
	deleted, err := s.pruneSnapshots(ctx, maxSnapshots, maxSnapshotAge, now)
	if err != nil {
		return err
	}
	slog.Info("cleanup: snapshots pruned", "deleted", deleted)
	metrics.SnapshotsPrunedTotal.Add(float64(deleted))

	gcDeleted, err := s.gcPool(ctx, now)
	if err != nil {
		return err
	}
	slog.Info("cleanup: pool GC complete", "orphaned_files_deleted", gcDeleted)
	metrics.GCFilesDeletedTotal.Add(float64(gcDeleted))

	srcDeleted, err := s.gcSrc(ctx, now)
	if err != nil {
		return err
	}
	slog.Info("cleanup: src GC complete", "orphaned_files_deleted", srcDeleted)
	metrics.GCFilesDeletedTotal.Add(float64(srcDeleted))
	return nil
}

func (s *Syncer) pruneSnapshots(ctx context.Context, maxSnapshots int, maxSnapshotAge time.Duration, now time.Time) (int, error) {
	// Both axes unconstrained: nothing to prune.
	if maxSnapshots == 0 && maxSnapshotAge == 0 {
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

	// Each axis defaults to "satisfied" when unconstrained (0), so an
	// unconstrained axis never blocks pruning on the other axis alone. The
	// both-unconstrained case that would make this trivially true for every
	// snapshot is already handled by the early return above.
	var toDelete []string
	for i, sn := range snaps {
		countOK := maxSnapshots == 0 || i >= maxSnapshots
		ageOK := maxSnapshotAge == 0 || now.Sub(sn.t) > maxSnapshotAge
		if countOK && ageOK {
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

// gcGracePeriod protects files written moments ago from being deleted by a
// concurrently-running GC pass. A pull-through/auto_update cache write does
// store.PutFile followed some time later by a metadata index commit; if a GC
// pass builds its "keep" reference set (from the index) in between those two
// steps, the just-written file is invisible to the ref set even though it now
// exists in storage, and would otherwise be deleted right after being cached.
// Configurable via schedule.gc_grace; see gcGracePeriod.
const defaultGCGracePeriod = 1 * time.Hour

// gcGracePeriod resolves schedule.gc_grace, falling back to
// defaultGCGracePeriod when unset, "0", or invalid. This is a safety margin
// against the race described above, not a feature meant to be casually
// disabled, so an empty/invalid value falls back to the safe default rather
// than to no grace period at all.
func (s *Syncer) gcGracePeriod() time.Duration {
	raw := s.cfg.Schedule.GCGrace
	if raw == "" || raw == "0" {
		return defaultGCGracePeriod
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid schedule.gc_grace, using default", "value", raw, "default", defaultGCGracePeriod, "err", err)
		return defaultGCGracePeriod
	}
	return d
}

// deleteOrphans deletes each candidate, skipping any candidate written within
// the configured GC grace period (see gcGracePeriod) since it may be
// mid-flight for a concurrent cache write. candidates carry the ModTime the
// caller already has on hand from listing (WalkPool/ListPublishedInfo), so
// this doesn't issue a separate Stat per file. kind labels log lines (e.g.
// "pool file", "src file"). Returns the number of files actually deleted.
func (s *Syncer) deleteOrphans(ctx context.Context, kind string, candidates []storage.FileInfo, now time.Time) int {
	grace := s.gcGracePeriod()
	deleted := 0
	for _, fi := range candidates {
		if now.Sub(fi.ModTime) < grace {
			slog.Debug("cleanup: skipping recently-written "+kind+" this run", "path", fi.Path)
			continue
		}
		if err := s.store.Delete(ctx, fi.Path); err != nil {
			slog.Warn("cleanup: delete orphaned "+kind+" failed", "path", fi.Path, "err", err)
			continue
		}
		slog.Debug("cleanup: deleted orphaned "+kind, "path", fi.Path)
		deleted++
	}
	return deleted
}

// maxOrphanRatio bounds what fraction of a pool/src scan gcPool/gcSrc will
// ever delete in one run. A correctly functioning reference set (built from
// real published snapshots plus the metadata index) should only ever orphan
// a small tail of superseded/abandoned files. If most or all scanned files
// look unreferenced, that's overwhelmingly a sign the reference set itself
// is broken -- an empty/thin metadata index, or snapshots that have been
// publishing empty content -- not that the pool suddenly turned into
// garbage. Refusing to delete in that case trades a skipped GC cycle (cheap,
// recoverable next run) for what would otherwise be irreversible data loss.
// This exists because exactly that happened: a silently-empty metadata index
// drove gcPool to delete a multi-gigabyte pool down to a few tens of
// megabytes, one weekly cleanup at a time, with nothing to stop it.
const maxOrphanRatio = 0.5

// minFilesForRatioCheck: below this many scanned files, a ratio judgment is
// too noisy to be meaningful (a handful of superseded versions in a small
// pool can easily exceed maxOrphanRatio while being completely routine) --
// the safety check only engages once there's enough volume for the ratio to
// mean something.
const minFilesForRatioCheck = 50

// checkOrphanRatio reports whether gcPool/gcSrc should abort this run rather
// than delete, based on maxOrphanRatio. Logs at ERROR (not Warn, since this
// is not routine housekeeping) and increments metrics.GCAbortedTotal so it's
// visible/alertable -- an abort here should never pass silently.
func checkOrphanRatio(kind string, total, orphaned int) bool {
	if total < minFilesForRatioCheck {
		return false
	}
	ratio := float64(orphaned) / float64(total)
	if ratio <= maxOrphanRatio {
		return false
	}
	slog.Error("cleanup: refusing to GC, orphan ratio implausibly high -- reference set (metadata index/snapshots) may be broken",
		"kind", kind, "total_files", total, "orphaned", orphaned, "ratio", ratio, "max_allowed_ratio", maxOrphanRatio)
	metrics.GCAbortedTotal.WithLabelValues(kind).Inc()
	return true
}

// gcPool removes pool files not referenced by any remaining snapshot or the
// metadata index, and returns the number of files deleted. Candidates newer
// than gcGracePeriod are skipped this run (see gcGracePeriod). Aborts
// (deleting nothing) if the orphan ratio looks implausibly high -- see
// checkOrphanRatio.
func (s *Syncer) gcPool(ctx context.Context, now time.Time) (int, error) {
	ref, err := s.buildPoolRefSet(ctx)
	if err != nil {
		return 0, err
	}

	var candidates []storage.FileInfo
	var total int
	if err := s.store.WalkPool(ctx, func(info storage.FileInfo) error {
		total++
		if !ref[info.Path] {
			candidates = append(candidates, info)
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("walk pool: %w", err)
	}

	if checkOrphanRatio("pool", total, len(candidates)) {
		return 0, nil
	}

	return s.deleteOrphans(ctx, "pool file", candidates, now), nil
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

	// Also include the pool path of the highest version of each package known
	// to the metadata index (belt-and-suspenders for packages downloaded since
	// the last snapshot). Superseded versions are deliberately excluded: once
	// a newer version is indexed, the old one is never published again (see
	// groupStanzas in syncer.go, which does the same highest-version dedup),
	// so protecting its pool file here forever would only accumulate disk
	// usage with no purpose -- EntryByDigest, the only mechanism that could
	// have needed old-version entries for content-dedup, is unused.
	entries, err := s.index.ListEntries(ctx, model.Selector{})
	if err != nil {
		return nil, fmt.Errorf("list metadata entries: %w", err)
	}
	type entryKey struct{ os, codename, comp, arch, pkg string }
	best := highestVersionByKey(entries,
		func(e model.IndexEntry) entryKey { return entryKey{e.OS, e.Codename, e.Component, e.Arch, e.Package} },
		func(e model.IndexEntry) string { return e.Version })
	for _, e := range best {
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
	sc.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB  -- handles long Depends: lines
	for sc.Scan() {
		if fn, ok := strings.CutPrefix(sc.Text(), "Filename: "); ok {
			ref[fn] = true
		}
	}
	return sc.Err()
}

// gcSrc removes src/ files not referenced by any remaining snapshot or the
// metadata source index, and returns the number of files deleted. Candidates
// newer than gcGracePeriod are skipped this run (see gcGracePeriod). Aborts
// (deleting nothing) if the orphan ratio looks implausibly high -- see
// checkOrphanRatio.
func (s *Syncer) gcSrc(ctx context.Context, now time.Time) (int, error) {
	ref, err := s.buildSrcRefSet(ctx)
	if err != nil {
		return 0, err
	}

	// src/ files are stored via FileStore (PutFile), so list them via
	// ListPublishedInfo which walks the same storage root.
	allSrc, err := s.store.ListPublishedInfo(ctx, "src")
	if err != nil {
		return 0, fmt.Errorf("list src files: %w", err)
	}

	var candidates []storage.FileInfo
	for _, fi := range allSrc {
		if !ref[fi.Path] {
			candidates = append(candidates, fi)
		}
	}

	if checkOrphanRatio("src", len(allSrc), len(candidates)) {
		return 0, nil
	}

	return s.deleteOrphans(ctx, "src file", candidates, now), nil
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

	// Also include all src paths for the highest version of each source
	// package known to the metadata index -- see buildPoolRefSet for why
	// superseded versions are deliberately excluded.
	srcEntries, err := s.index.ListSourceEntries(ctx, model.Selector{})
	if err != nil {
		return nil, fmt.Errorf("list source entries: %w", err)
	}
	type srcKey struct{ os, codename, comp, pkg string }
	bestSrc := highestVersionByKey(srcEntries,
		func(e model.SourceEntry) srcKey { return srcKey{e.OS, e.Codename, e.Component, e.Package} },
		func(e model.SourceEntry) string { return e.Version })
	for _, e := range bestSrc {
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

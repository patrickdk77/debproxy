// Package deb822store implements MetadataIndex as zstd-compressed deb822 files
// held entirely in memory, persisted through the storage backend on every write.
//
// Layout:
//
//	metadata/index/{os}/{codename}/{component}/{arch}.packages.zst
//	metadata/upstream/{upstream}.state.zst
package deb822store

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/debversion"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

const (
	indexPrefix    = "metadata/index/"
	upstreamPrefix = "metadata/upstream/"
	sourcesSuffix  = "/sources.zst"
)

// Store is an in-memory MetadataIndex backed by deb822+zstd files.
// Writes are deferred: mutations mark keys dirty and a background goroutine
// (or explicit Flush call) persists them periodically.
type Store struct {
	backend      storage.Storage
	mu           sync.RWMutex
	entries      map[string][]model.IndexEntry           // key: "os/codename/component/arch"
	states       map[string][]model.UpstreamPackageState // key: upstream name
	sources      map[string][]model.SourceEntry          // key: "os/codename/component"
	fileModTimes map[string]time.Time                    // relPath -> mod time at last load
	dirty        map[string]bool                         // relPath -> needs flush
}

// New loads all existing metadata from the storage backend into memory.
func New(ctx context.Context, backend storage.Storage) (*Store, error) {
	s := &Store{
		backend:      backend,
		entries:      map[string][]model.IndexEntry{},
		states:       map[string][]model.UpstreamPackageState{},
		sources:      map[string][]model.SourceEntry{},
		fileModTimes: map[string]time.Time{},
		dirty:        map[string]bool{},
	}
	if err := s.loadAll(ctx); err != nil {
		return nil, err
	}
	var totalPkgs int
	for _, entries := range s.entries {
		totalPkgs += len(entries)
	}
	slog.Info("metadata loaded", "packages", totalPkgs, "buckets", len(s.entries), "upstream_states", len(s.states))
	return s, nil
}

func (s *Store) loadAll(ctx context.Context) error {
	paths, err := s.backend.ListPublished(ctx, "metadata/")
	if err != nil {
		return err
	}
	for _, p := range paths {
		switch {
		case strings.HasPrefix(p, indexPrefix) && strings.HasSuffix(p, ".packages.zst"):
			if err := s.loadIndexFile(ctx, p); err != nil {
				return fmt.Errorf("load %s: %w", p, err)
			}
		case strings.HasPrefix(p, indexPrefix) && strings.HasSuffix(p, sourcesSuffix):
			if err := s.loadSourcesFile(ctx, p); err != nil {
				return fmt.Errorf("load %s: %w", p, err)
			}
		case strings.HasPrefix(p, upstreamPrefix) && strings.HasSuffix(p, ".state.zst"):
			if err := s.loadStateFile(ctx, p); err != nil {
				return fmt.Errorf("load %s: %w", p, err)
			}
		default:
			continue
		}
		fi, err := s.backend.StatPublished(ctx, p)
		if err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		s.fileModTimes[p] = fi.ModTime
	}
	return nil
}

// Refresh merges any metadata files that have been written since the last load
// into the in-memory state, and evicts entries for files that no longer exist.
// Uses merge semantics (our in-memory version wins on conflict) so it is safe
// to call with dirty in-memory state  -- no pending writes are lost.
func (s *Store) Refresh(ctx context.Context) error {
	paths, err := s.backend.ListPublished(ctx, "metadata/")
	if err != nil {
		return err
	}

	// Stat all relevant files without holding the lock.
	type pendingLoad struct {
		relPath string
		modTime time.Time
	}
	seen := make(map[string]bool, len(paths))
	var toLoad []pendingLoad

	for _, p := range paths {
		isIndex := strings.HasPrefix(p, indexPrefix) && strings.HasSuffix(p, ".packages.zst")
		isSrc := strings.HasPrefix(p, indexPrefix) && strings.HasSuffix(p, sourcesSuffix)
		isState := strings.HasPrefix(p, upstreamPrefix) && strings.HasSuffix(p, ".state.zst")
		if !isIndex && !isSrc && !isState {
			continue
		}
		seen[p] = true
		fi, err := s.backend.StatPublished(ctx, p)
		if err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		s.mu.RLock()
		known := s.fileModTimes[p]
		s.mu.RUnlock()
		if fi.ModTime.After(known) {
			toLoad = append(toLoad, pendingLoad{p, fi.ModTime})
		}
	}

	// Determine deleted files.
	s.mu.RLock()
	var toEvict []string
	for p := range s.fileModTimes {
		if !seen[p] {
			toEvict = append(toEvict, p)
		}
	}
	s.mu.RUnlock()

	if len(toLoad) == 0 && len(toEvict) == 0 {
		return nil
	}

	// Merge each changed file. mergeFromDisk does its own locking so no I/O
	// is performed while holding the write lock.
	for _, pl := range toLoad {
		if err := s.mergeFromDisk(ctx, pl.relPath); err != nil {
			return fmt.Errorf("refresh %s: %w", pl.relPath, err)
		}
		s.mu.Lock()
		s.fileModTimes[pl.relPath] = pl.modTime
		s.mu.Unlock()
	}

	if len(toEvict) > 0 {
		s.mu.Lock()
		for _, p := range toEvict {
			s.evictFile(p)
			delete(s.fileModTimes, p)
		}
		s.mu.Unlock()
	}

	return nil
}

// evictFile removes the in-memory data for a metadata file that no longer exists.
// Must be called with s.mu held for writing.
func (s *Store) evictFile(relPath string) {
	if strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, ".packages.zst") {
		key := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), ".packages.zst")
		delete(s.entries, key)
	} else if strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, sourcesSuffix) {
		key := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), sourcesSuffix)
		delete(s.sources, key)
	} else if strings.HasPrefix(relPath, upstreamPrefix) && strings.HasSuffix(relPath, ".state.zst") {
		upstream := strings.TrimSuffix(strings.TrimPrefix(relPath, upstreamPrefix), ".state.zst")
		delete(s.states, upstream)
	}
}

func (s *Store) loadIndexFile(ctx context.Context, relPath string) error {
	inner := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), ".packages.zst")
	parts := strings.SplitN(inner, "/", 4)
	if len(parts) != 4 {
		return fmt.Errorf("unexpected index path: %s", relPath)
	}
	osName, codename, component, arch := parts[0], parts[1], parts[2], parts[3]
	entries, err := readIndexEntries(ctx, s.backend, relPath, osName, codename, component, arch)
	if err != nil {
		return err
	}
	s.entries[entryKey(osName, codename, component, arch)] = entries
	return nil
}

func (s *Store) loadStateFile(ctx context.Context, relPath string) error {
	upstreamName := strings.TrimSuffix(strings.TrimPrefix(relPath, upstreamPrefix), ".state.zst")
	states, err := readUpstreamStates(ctx, s.backend, relPath, upstreamName)
	if err != nil {
		return err
	}
	s.states[upstreamName] = states
	return nil
}

// readIndexEntries reads and parses an index file without touching Store state.
func readIndexEntries(ctx context.Context, backend storage.Storage, relPath, osName, codename, component, arch string) ([]model.IndexEntry, error) {
	rc, err := backend.OpenPublished(ctx, relPath)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	zr, err := zstd.NewReader(rc)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	paras, err := apt.ParseParagraphs(zr)
	if err != nil {
		return nil, err
	}
	entries := make([]model.IndexEntry, 0, len(paras))
	for _, p := range paras {
		entries = append(entries, entryFromParagraph(osName, codename, component, arch, p))
	}
	return entries, nil
}

// readUpstreamStates reads and parses an upstream state file without touching Store state.
func readUpstreamStates(ctx context.Context, backend storage.Storage, relPath, upstreamName string) ([]model.UpstreamPackageState, error) {
	rc, err := backend.OpenPublished(ctx, relPath)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	zr, err := zstd.NewReader(rc)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	paras, err := apt.ParseParagraphs(zr)
	if err != nil {
		return nil, err
	}
	states := make([]model.UpstreamPackageState, 0, len(paras))
	for _, p := range paras {
		states = append(states, stateFromParagraph(upstreamName, p))
	}
	return states, nil
}

func (s *Store) Ping(context.Context) error    { return nil }
func (s *Store) Migrate(context.Context) error { return nil }

func (s *Store) Reset(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = map[string][]model.IndexEntry{}
	s.states = map[string][]model.UpstreamPackageState{}
	s.sources = map[string][]model.SourceEntry{}
	return nil
}

func (s *Store) UpsertEntry(_ context.Context, e model.IndexEntry) error {
	if e.FirstSeen.IsZero() {
		e.FirstSeen = metadata.Now()
	}
	key := entryKey(e.OS, e.Codename, e.Component, e.Arch)

	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[key]
	updated := false
	for i, existing := range entries {
		if existing.Package == e.Package && existing.Version == e.Version {
			entries[i] = e
			updated = true
			break
		}
	}
	if !updated {
		entries = append(entries, e)
	}
	s.entries[key] = entries
	s.dirty[path.Join(indexPrefix, e.OS, e.Codename, e.Component, e.Arch+".packages.zst")] = true
	return nil
}

func (s *Store) ListEntries(ctx context.Context, sel model.Selector) ([]model.IndexEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []model.IndexEntry
	for key, entries := range s.entries {
		osName, codename, component, arch, ok := splitEntryKey(key)
		if !ok {
			continue
		}
		if sel.OS != "" && sel.OS != osName {
			continue
		}
		if sel.Codename != "" && sel.Codename != codename {
			continue
		}
		if sel.Component != "" && sel.Component != component {
			continue
		}
		if sel.Arch != "" && sel.Arch != arch {
			continue
		}
		out = append(out, entries...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return debversion.Compare(out[i].Version, out[j].Version) < 0
	})
	return out, nil
}

func (s *Store) EntryByDigest(_ context.Context, digest model.Digest) (*model.IndexEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entries := range s.entries {
		for _, e := range entries {
			if e.Checksums.SHA256 == digest {
				cp := e
				return &cp, nil
			}
		}
	}
	return nil, nil
}

func (s *Store) FindEntry(_ context.Context, sel model.Selector, pkg, version string) (*model.IndexEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *model.IndexEntry
	for key, entries := range s.entries {
		osName, codename, component, arch, ok := splitEntryKey(key)
		if !ok {
			continue
		}
		if sel.OS != "" && sel.OS != osName {
			continue
		}
		if sel.Codename != "" && sel.Codename != codename {
			continue
		}
		if sel.Component != "" && sel.Component != component {
			continue
		}
		if sel.Arch != "" && sel.Arch != arch {
			continue
		}
		for _, e := range entries {
			if e.Package != pkg {
				continue
			}
			if version != "" {
				if e.Version == version {
					cp := e
					return &cp, nil
				}
				continue
			}
			if best == nil || debversion.Compare(e.Version, best.Version) > 0 {
				cp := e
				best = &cp
			}
		}
	}
	return best, nil
}

func (s *Store) UpsertUpstreamState(_ context.Context, st model.UpstreamPackageState) error {
	if st.LastChecked.IsZero() {
		st.LastChecked = metadata.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	states := s.states[st.Upstream]
	updated := false
	for i, existing := range states {
		if existing.PackageName == st.PackageName && existing.Arch == st.Arch {
			states[i] = st
			updated = true
			break
		}
	}
	if !updated {
		states = append(states, st)
	}
	s.states[st.Upstream] = states
	s.dirty[upstreamPrefix+st.Upstream+".state.zst"] = true
	return nil
}

func (s *Store) GetUpstreamState(_ context.Context, upstream, name, arch string) (*model.UpstreamPackageState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.states[upstream] {
		if st.PackageName == name && st.Arch == arch {
			cp := st
			return &cp, nil
		}
	}
	return nil, nil
}

// --- persistence ---

// Flush writes all dirty in-memory entries and upstream states to the backing
// store. Called explicitly before a snapshot and by the periodic background
// goroutine.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.dirty) == 0 {
		s.mu.Unlock()
		return nil
	}
	dirty := make(map[string]bool, len(s.dirty))
	for k := range s.dirty {
		dirty[k] = true
	}
	s.mu.Unlock()

	for relPath := range dirty {
		if err := s.flushRelPath(ctx, relPath); err != nil {
			return err
		}
		s.mu.Lock()
		delete(s.dirty, relPath)
		s.mu.Unlock()
	}
	slog.Info("metadata saved", "files", len(dirty))
	return nil
}

func (s *Store) flushRelPath(ctx context.Context, relPath string) error {
	// If the on-disk file is newer than when we last read it, another instance
	// may have written changes we don't have in memory. Merge before overwriting
	// so no data is lost when running multiple servers or a cronjob alongside.
	s.mu.RLock()
	knownModTime := s.fileModTimes[relPath]
	s.mu.RUnlock()

	if fi, err := s.backend.StatPublished(ctx, relPath); err == nil && fi.ModTime.After(knownModTime) {
		if err := s.mergeFromDisk(ctx, relPath); err != nil {
			slog.Warn("pre-flush merge from disk", "path", relPath, "err", err)
			// Non-fatal: proceed with our own in-memory state rather than blocking.
		}
	}

	if err := s.writeRelPath(ctx, relPath); err != nil {
		return err
	}

	// Update fileModTimes so the next flush won't re-merge unnecessarily.
	if fi, err := s.backend.StatPublished(ctx, relPath); err == nil {
		s.mu.Lock()
		s.fileModTimes[relPath] = fi.ModTime
		s.mu.Unlock()
	}
	return nil
}

// writeRelPath serializes and writes the current in-memory state for relPath.
// It copies the slice under the read lock then writes to the backend without
// holding any lock, so slow storage calls don't block mutations.
func (s *Store) writeRelPath(ctx context.Context, relPath string) error {
	switch {
	case strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, ".packages.zst"):
		key := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), ".packages.zst")
		parts := strings.SplitN(key, "/", 4)
		if len(parts) != 4 {
			return fmt.Errorf("invalid index key %q", key)
		}
		s.mu.RLock()
		entries := append([]model.IndexEntry(nil), s.entries[key]...)
		s.mu.RUnlock()
		return s.flushEntries(ctx, parts[0], parts[1], parts[2], parts[3], entries)
	case strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, sourcesSuffix):
		key := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), sourcesSuffix)
		parts := strings.SplitN(key, "/", 3)
		if len(parts) != 3 {
			return fmt.Errorf("invalid sources key %q", key)
		}
		s.mu.RLock()
		srcs := append([]model.SourceEntry(nil), s.sources[key]...)
		s.mu.RUnlock()
		return s.flushSources(ctx, parts[0], parts[1], parts[2], srcs)
	case strings.HasPrefix(relPath, upstreamPrefix) && strings.HasSuffix(relPath, ".state.zst"):
		up := strings.TrimSuffix(strings.TrimPrefix(relPath, upstreamPrefix), ".state.zst")
		s.mu.RLock()
		states := append([]model.UpstreamPackageState(nil), s.states[up]...)
		s.mu.RUnlock()
		return s.flushStates(ctx, up, states)
	}
	return nil
}

// mergeFromDisk reads relPath from the backend and merges its contents into the
// in-memory state. For any entry with the same key in both sources, our
// in-memory version wins (it represents more recent work by this instance).
func (s *Store) mergeFromDisk(ctx context.Context, relPath string) error {
	switch {
	case strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, ".packages.zst"):
		inner := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), ".packages.zst")
		parts := strings.SplitN(inner, "/", 4)
		if len(parts) != 4 {
			return fmt.Errorf("unexpected path: %s", relPath)
		}
		osName, codename, component, arch := parts[0], parts[1], parts[2], parts[3]
		disk, err := readIndexEntries(ctx, s.backend, relPath, osName, codename, component, arch)
		if err != nil {
			return err
		}
		key := entryKey(osName, codename, component, arch)
		s.mu.Lock()
		s.entries[key] = mergeIndexEntries(disk, s.entries[key])
		s.mu.Unlock()
	case strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, sourcesSuffix):
		inner := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), sourcesSuffix)
		parts := strings.SplitN(inner, "/", 3)
		if len(parts) != 3 {
			return fmt.Errorf("unexpected path: %s", relPath)
		}
		osName, codename, component := parts[0], parts[1], parts[2]
		disk, err := readSourceEntries(ctx, s.backend, relPath, osName, codename, component)
		if err != nil {
			return err
		}
		key := sourceKey(osName, codename, component)
		s.mu.Lock()
		s.sources[key] = mergeSourceEntries(disk, s.sources[key])
		s.mu.Unlock()
	case strings.HasPrefix(relPath, upstreamPrefix) && strings.HasSuffix(relPath, ".state.zst"):
		upstreamName := strings.TrimSuffix(strings.TrimPrefix(relPath, upstreamPrefix), ".state.zst")
		disk, err := readUpstreamStates(ctx, s.backend, relPath, upstreamName)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.states[upstreamName] = mergeUpstreamStates(disk, s.states[upstreamName])
		s.mu.Unlock()
	}
	return nil
}

// mergeIndexEntries returns the union of disk and memory entries.
// For the same (Package, Version), the memory entry wins.
func mergeIndexEntries(disk, memory []model.IndexEntry) []model.IndexEntry {
	type pk struct{ pkg, ver string }
	mem := make(map[pk]model.IndexEntry, len(memory))
	for _, e := range memory {
		mem[pk{e.Package, e.Version}] = e
	}
	out := make([]model.IndexEntry, 0, len(disk)+len(memory))
	for _, e := range disk {
		k := pk{e.Package, e.Version}
		if m, ok := mem[k]; ok {
			out = append(out, m)
			delete(mem, k)
		} else {
			out = append(out, e)
		}
	}
	for _, e := range mem {
		out = append(out, e)
	}
	return out
}

// mergeUpstreamStates returns the union of disk and memory states.
// For the same (PackageName, Arch), the memory state wins.
func mergeUpstreamStates(disk, memory []model.UpstreamPackageState) []model.UpstreamPackageState {
	type pk struct{ name, arch string }
	mem := make(map[pk]model.UpstreamPackageState, len(memory))
	for _, st := range memory {
		mem[pk{st.PackageName, st.Arch}] = st
	}
	out := make([]model.UpstreamPackageState, 0, len(disk)+len(memory))
	for _, st := range disk {
		k := pk{st.PackageName, st.Arch}
		if m, ok := mem[k]; ok {
			out = append(out, m)
			delete(mem, k)
		} else {
			out = append(out, st)
		}
	}
	for _, st := range mem {
		out = append(out, st)
	}
	return out
}

// StartPeriodicFlush launches a background goroutine that calls Flush every
// interval. The returned stop function flushes once more and waits for the
// goroutine to exit. Call it on graceful shutdown.
func (s *Store) StartPeriodicFlush(ctx context.Context, interval time.Duration) func() {
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := s.Flush(ctx); err != nil {
					slog.Warn("periodic metadata flush failed", "err", err)
				}
			case <-stop:
				if err := s.Flush(ctx); err != nil {
					slog.Error("final metadata flush failed", "err", err)
				}
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}


func (s *Store) flushEntries(ctx context.Context, osName, codename, component, arch string, entries []model.IndexEntry) error {
	relPath := path.Join(indexPrefix, osName, codename, component, arch+".packages.zst")
	data, err := serializeEntries(entries)
	if err != nil {
		return err
	}
	return s.backend.WriteFile(ctx, relPath, bytes.NewReader(data), int64(len(data)))
}

func (s *Store) flushStates(ctx context.Context, upstream string, states []model.UpstreamPackageState) error {
	relPath := upstreamPrefix + upstream + ".state.zst"
	data, err := serializeStates(states)
	if err != nil {
		return err
	}
	return s.backend.WriteFile(ctx, relPath, bytes.NewReader(data), int64(len(data)))
}

func serializeEntries(entries []model.IndexEntry) ([]byte, error) {
	paras := make([]*apt.Paragraph, len(entries))
	for i, e := range entries {
		paras[i] = entryToParagraph(e)
	}
	return compress(paras)
}

func serializeStates(states []model.UpstreamPackageState) ([]byte, error) {
	paras := make([]*apt.Paragraph, len(states))
	for i, st := range states {
		paras[i] = stateToParagraph(st)
	}
	return compress(paras)
}

func compress(paras []*apt.Paragraph) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if err := apt.WriteParagraphs(zw, paras); err != nil {
		if cerr := zw.Close(); cerr != nil {
			slog.Warn("zstd writer close after write error", "err", cerr)
		}
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- deb822 conversion ---

func entryToParagraph(e model.IndexEntry) *apt.Paragraph {
	p, err := apt.ParseStanza(e.Control)
	if err != nil {
		p = apt.NewParagraph()
		p.Set("Package", e.Package)
		p.Set("Version", e.Version)
		p.Set("Architecture", e.Arch)
		p.Set("Filename", e.PoolPath)
		p.Set("Size", strconv.FormatInt(e.Size, 10))
		p.Set("SHA256", string(e.Checksums.SHA256))
	}
	if e.Checksums.SHA512 != "" && !p.Has("SHA512") {
		p.Set("SHA512", string(e.Checksums.SHA512))
	}
	p.Set("X-Debproxy-Upstream", e.Upstream)
	p.Set("X-Debproxy-From-Auto-Update", strconv.FormatBool(e.FromAutoUpdate))
	p.Set("X-Debproxy-First-Seen", e.FirstSeen.UTC().Format(time.RFC3339))
	return p
}

func entryFromParagraph(osName, codename, component, arch string, p *apt.Paragraph) model.IndexEntry {
	clean := apt.NewParagraph()
	for _, k := range p.Keys() {
		if strings.HasPrefix(strings.ToLower(k), "x-debproxy-") {
			continue
		}
		clean.Set(k, p.Get(k))
	}
	control, _ := apt.StanzaString(clean)

	firstSeen, _ := time.Parse(time.RFC3339, p.Get("X-Debproxy-First-Seen"))
	fromAutoUpdate, _ := strconv.ParseBool(p.Get("X-Debproxy-From-Auto-Update"))
	size, _ := strconv.ParseInt(p.Get("Size"), 10, 64)

	return model.IndexEntry{
		OS:             osName,
		Codename:       codename,
		Component:      component,
		Arch:           arch,
		Package:        p.Get("Package"),
		Version:        p.Get("Version"),
		Upstream:       p.Get("X-Debproxy-Upstream"),
		FromAutoUpdate: fromAutoUpdate,
		PoolPath:       p.Get("Filename"),
		Checksums: model.Checksums{
			SHA256: model.Digest(p.Get("SHA256")),
			SHA512: model.Digest(p.Get("SHA512")),
		},
		Size:      size,
		Control:   control,
		FirstSeen: firstSeen,
	}
}

func stateToParagraph(st model.UpstreamPackageState) *apt.Paragraph {
	p := apt.NewParagraph()
	p.Set("Package", st.PackageName)
	p.Set("Architecture", st.Arch)
	p.Set("Version", st.UpstreamVersion)
	p.Set("X-Debproxy-Last-Checked", st.LastChecked.UTC().Format(time.RFC3339))
	return p
}

func stateFromParagraph(upstream string, p *apt.Paragraph) model.UpstreamPackageState {
	lastChecked, _ := time.Parse(time.RFC3339, p.Get("X-Debproxy-Last-Checked"))
	return model.UpstreamPackageState{
		Upstream:        upstream,
		PackageName:     p.Get("Package"),
		Arch:            p.Get("Architecture"),
		UpstreamVersion: p.Get("Version"),
		LastChecked:     lastChecked,
	}
}

// --- source entry methods ---

func (s *Store) UpsertSourceEntry(_ context.Context, e model.SourceEntry) error {
	if e.FirstSeen.IsZero() {
		e.FirstSeen = metadata.Now()
	}
	key := sourceKey(e.OS, e.Codename, e.Component)
	relPath := sourceRelPath(e.OS, e.Codename, e.Component)

	s.mu.Lock()
	defer s.mu.Unlock()

	srcs := s.sources[key]
	updated := false
	for i, existing := range srcs {
		if existing.Package == e.Package && existing.Version == e.Version {
			srcs[i] = e
			updated = true
			break
		}
	}
	if !updated {
		srcs = append(srcs, e)
	}
	s.sources[key] = srcs
	s.dirty[relPath] = true
	return nil
}

func (s *Store) ListSourceEntries(_ context.Context, sel model.Selector) ([]model.SourceEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []model.SourceEntry
	for key, srcs := range s.sources {
		osName, codename, component, ok := splitSourceKey(key)
		if !ok {
			continue
		}
		if sel.OS != "" && sel.OS != osName {
			continue
		}
		if sel.Codename != "" && sel.Codename != codename {
			continue
		}
		if sel.Component != "" && sel.Component != component {
			continue
		}
		out = append(out, srcs...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return debversion.Compare(out[i].Version, out[j].Version) < 0
	})
	return out, nil
}

func (s *Store) FindSourceEntry(_ context.Context, sel model.Selector, pkg, version string) (*model.SourceEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *model.SourceEntry
	for key, srcs := range s.sources {
		osName, codename, component, ok := splitSourceKey(key)
		if !ok {
			continue
		}
		if sel.OS != "" && sel.OS != osName {
			continue
		}
		if sel.Codename != "" && sel.Codename != codename {
			continue
		}
		if sel.Component != "" && sel.Component != component {
			continue
		}
		for _, e := range srcs {
			if e.Package != pkg {
				continue
			}
			if version != "" {
				if e.Version == version {
					cp := e
					return &cp, nil
				}
				continue
			}
			if best == nil || debversion.Compare(e.Version, best.Version) > 0 {
				cp := e
				best = &cp
			}
		}
	}
	return best, nil
}

func (s *Store) loadSourcesFile(ctx context.Context, relPath string) error {
	inner := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), sourcesSuffix)
	parts := strings.SplitN(inner, "/", 3)
	if len(parts) != 3 {
		return fmt.Errorf("unexpected sources path: %s", relPath)
	}
	osName, codename, component := parts[0], parts[1], parts[2]
	srcs, err := readSourceEntries(ctx, s.backend, relPath, osName, codename, component)
	if err != nil {
		return err
	}
	s.sources[sourceKey(osName, codename, component)] = srcs
	return nil
}

func readSourceEntries(ctx context.Context, backend storage.Storage, relPath, osName, codename, component string) ([]model.SourceEntry, error) {
	rc, err := backend.OpenPublished(ctx, relPath)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	zr, err := zstd.NewReader(rc)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	paras, err := apt.ParseParagraphs(zr)
	if err != nil {
		return nil, err
	}
	srcs := make([]model.SourceEntry, 0, len(paras))
	for _, p := range paras {
		srcs = append(srcs, sourceEntryFromParagraph(osName, codename, component, p))
	}
	return srcs, nil
}

func (s *Store) flushSources(ctx context.Context, osName, codename, component string, srcs []model.SourceEntry) error {
	relPath := sourceRelPath(osName, codename, component)
	data, err := serializeSources(srcs)
	if err != nil {
		return err
	}
	return s.backend.WriteFile(ctx, relPath, bytes.NewReader(data), int64(len(data)))
}

func serializeSources(srcs []model.SourceEntry) ([]byte, error) {
	paras := make([]*apt.Paragraph, len(srcs))
	for i, e := range srcs {
		paras[i] = sourceEntryToParagraph(e)
	}
	return compress(paras)
}

func sourceEntryToParagraph(e model.SourceEntry) *apt.Paragraph {
	p := apt.NewParagraph()
	p.Set("Package", e.Package)
	p.Set("Version", e.Version)
	p.Set("X-Debproxy-Upstream", e.Upstream)
	p.Set("X-Debproxy-Local-Dir", e.LocalDir)
	p.Set("X-Debproxy-Upstream-Dir", e.UpstreamDir)
	p.Set("X-Debproxy-First-Seen", e.FirstSeen.UTC().Format(time.RFC3339))
	p.Set("X-Debproxy-Stanza", e.Stanza)
	for i, f := range e.Files {
		p.Set(fmt.Sprintf("X-Debproxy-File-%d", i),
			fmt.Sprintf("%s %d %s", f.Filename, f.Size, string(f.SHA256)))
	}
	return p
}

func sourceEntryFromParagraph(osName, codename, component string, p *apt.Paragraph) model.SourceEntry {
	stanza := strings.TrimPrefix(p.Get("X-Debproxy-Stanza"), "\n")
	firstSeen, _ := time.Parse(time.RFC3339, p.Get("X-Debproxy-First-Seen"))

	var files []model.SourceFile
	for i := 0; ; i++ {
		v := p.Get(fmt.Sprintf("X-Debproxy-File-%d", i))
		if v == "" {
			break
		}
		parts := strings.Fields(v)
		if len(parts) != 3 {
			break
		}
		size, _ := strconv.ParseInt(parts[1], 10, 64)
		files = append(files, model.SourceFile{
			Filename: parts[0],
			Size:     size,
			SHA256:   model.Digest(parts[2]),
		})
	}

	return model.SourceEntry{
		OS:          osName,
		Codename:    codename,
		Component:   component,
		Package:     p.Get("Package"),
		Version:     p.Get("Version"),
		Upstream:    p.Get("X-Debproxy-Upstream"),
		LocalDir:    p.Get("X-Debproxy-Local-Dir"),
		UpstreamDir: p.Get("X-Debproxy-Upstream-Dir"),
		Files:       files,
		Stanza:      stanza,
		FirstSeen:   firstSeen,
	}
}

func mergeSourceEntries(disk, memory []model.SourceEntry) []model.SourceEntry {
	type pk struct{ pkg, ver string }
	mem := make(map[pk]model.SourceEntry, len(memory))
	for _, e := range memory {
		mem[pk{e.Package, e.Version}] = e
	}
	out := make([]model.SourceEntry, 0, len(disk)+len(memory))
	for _, e := range disk {
		k := pk{e.Package, e.Version}
		if m, ok := mem[k]; ok {
			out = append(out, m)
			delete(mem, k)
		} else {
			out = append(out, e)
		}
	}
	for _, e := range mem {
		out = append(out, e)
	}
	return out
}

// --- key helpers ---

func entryKey(osName, codename, component, arch string) string {
	return osName + "/" + codename + "/" + component + "/" + arch
}

func splitEntryKey(key string) (osName, codename, component, arch string, ok bool) {
	parts := strings.SplitN(key, "/", 4)
	if len(parts) != 4 {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func sourceKey(osName, codename, component string) string {
	return osName + "/" + codename + "/" + component
}

func splitSourceKey(key string) (osName, codename, component string, ok bool) {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func sourceRelPath(osName, codename, component string) string {
	return path.Join(indexPrefix, osName, codename, component) + sourcesSuffix
}

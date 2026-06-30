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
)

// Store is an in-memory MetadataIndex backed by deb822+zstd files.
// Writes are deferred: mutations mark keys dirty and a background goroutine
// (or explicit Flush call) persists them periodically.
type Store struct {
	backend      storage.Storage
	mu           sync.RWMutex
	entries      map[string][]model.IndexEntry           // key: "os/codename/component/arch"
	states       map[string][]model.UpstreamPackageState // key: upstream name
	fileModTimes map[string]time.Time                    // relPath -> mod time at last load
	dirty        map[string]bool                         // relPath -> needs flush
}

// New loads all existing metadata from the storage backend into memory.
func New(ctx context.Context, backend storage.Storage) (*Store, error) {
	s := &Store{
		backend:      backend,
		entries:      map[string][]model.IndexEntry{},
		states:       map[string][]model.UpstreamPackageState{},
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

// Refresh reloads any metadata files that have been written since the last load
// and evicts entries for files that no longer exist. Safe to call concurrently.
func (s *Store) Refresh(ctx context.Context) error {
	paths, err := s.backend.ListPublished(ctx, "metadata/")
	if err != nil {
		return err
	}

	// Stat all relevant files without holding the lock; collect what needs reloading.
	type pendingLoad struct {
		relPath string
		modTime time.Time
	}
	seen := make(map[string]bool, len(paths))
	var toLoad []pendingLoad

	for _, p := range paths {
		isIndex := strings.HasPrefix(p, indexPrefix) && strings.HasSuffix(p, ".packages.zst")
		isState := strings.HasPrefix(p, upstreamPrefix) && strings.HasSuffix(p, ".state.zst")
		if !isIndex && !isState {
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

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, pl := range toLoad {
		switch {
		case strings.HasPrefix(pl.relPath, indexPrefix):
			if err := s.loadIndexFile(ctx, pl.relPath); err != nil {
				return fmt.Errorf("refresh %s: %w", pl.relPath, err)
			}
		case strings.HasPrefix(pl.relPath, upstreamPrefix):
			if err := s.loadStateFile(ctx, pl.relPath); err != nil {
				return fmt.Errorf("refresh %s: %w", pl.relPath, err)
			}
		}
		s.fileModTimes[pl.relPath] = pl.modTime
	}

	for _, p := range toEvict {
		s.evictFile(p)
		delete(s.fileModTimes, p)
	}

	return nil
}

// evictFile removes the in-memory data for a metadata file that no longer exists.
// Must be called with s.mu held for writing.
func (s *Store) evictFile(relPath string) {
	if strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, ".packages.zst") {
		key := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), ".packages.zst")
		delete(s.entries, key)
	} else if strings.HasPrefix(relPath, upstreamPrefix) && strings.HasSuffix(relPath, ".state.zst") {
		upstream := strings.TrimSuffix(strings.TrimPrefix(relPath, upstreamPrefix), ".state.zst")
		delete(s.states, upstream)
	}
}

func (s *Store) loadIndexFile(ctx context.Context, relPath string) error {
	inner := strings.TrimPrefix(relPath, indexPrefix)
	inner = strings.TrimSuffix(inner, ".packages.zst")
	parts := strings.SplitN(inner, "/", 4)
	if len(parts) != 4 {
		return fmt.Errorf("unexpected index path: %s", relPath)
	}
	osName, codename, component, arch := parts[0], parts[1], parts[2], parts[3]

	rc, err := s.backend.OpenPublished(ctx, relPath)
	if err != nil {
		return err
	}
	defer rc.Close()

	zr, err := zstd.NewReader(rc)
	if err != nil {
		return err
	}
	defer zr.Close()

	paras, err := apt.ParseParagraphs(zr)
	if err != nil {
		return err
	}

	entries := make([]model.IndexEntry, 0, len(paras))
	for _, p := range paras {
		entries = append(entries, entryFromParagraph(osName, codename, component, arch, p))
	}
	s.entries[entryKey(osName, codename, component, arch)] = entries
	return nil
}

func (s *Store) loadStateFile(ctx context.Context, relPath string) error {
	upstreamName := strings.TrimPrefix(relPath, upstreamPrefix)
	upstreamName = strings.TrimSuffix(upstreamName, ".state.zst")

	rc, err := s.backend.OpenPublished(ctx, relPath)
	if err != nil {
		return err
	}
	defer rc.Close()

	zr, err := zstd.NewReader(rc)
	if err != nil {
		return err
	}
	defer zr.Close()

	paras, err := apt.ParseParagraphs(zr)
	if err != nil {
		return err
	}

	states := make([]model.UpstreamPackageState, 0, len(paras))
	for _, p := range paras {
		states = append(states, stateFromParagraph(upstreamName, p))
	}
	s.states[upstreamName] = states
	return nil
}

func (s *Store) Ping(context.Context) error    { return nil }
func (s *Store) Migrate(context.Context) error { return nil }

func (s *Store) Reset(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = map[string][]model.IndexEntry{}
	s.states = map[string][]model.UpstreamPackageState{}
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
	return nil
}

func (s *Store) flushRelPath(ctx context.Context, relPath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch {
	case strings.HasPrefix(relPath, indexPrefix) && strings.HasSuffix(relPath, ".packages.zst"):
		key := strings.TrimSuffix(strings.TrimPrefix(relPath, indexPrefix), ".packages.zst")
		parts := strings.SplitN(key, "/", 4)
		if len(parts) != 4 {
			return fmt.Errorf("invalid index key %q", key)
		}
		return s.flushEntries(ctx, parts[0], parts[1], parts[2], parts[3], s.entries[key])
	case strings.HasPrefix(relPath, upstreamPrefix) && strings.HasSuffix(relPath, ".state.zst"):
		up := strings.TrimSuffix(strings.TrimPrefix(relPath, upstreamPrefix), ".state.zst")
		return s.flushStates(ctx, up, s.states[up])
	}
	return nil
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

// CommitSnapshot deletes the staging metadata files for osName now that a
// snapshot has been published for it. The in-memory state is preserved so the
// current process can continue serving /live and running Update jobs.
// On the next startup the index will be empty for this OS until a pull-through
// or Update repopulates it (or a rebuild is run).
func (s *Store) CommitSnapshot(ctx context.Context, osName string) error {
	paths, err := s.backend.ListPublished(ctx, indexPrefix+osName+"/")
	if err != nil {
		return err
	}
	for _, p := range paths {
		if !strings.HasSuffix(p, ".packages.zst") {
			continue
		}
		if err := s.backend.DeletePublished(ctx, p); err != nil {
			return fmt.Errorf("delete staging %s: %w", p, err)
		}
		s.mu.Lock()
		delete(s.dirty, p)
		delete(s.fileModTimes, p)
		s.mu.Unlock()
	}
	return nil
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

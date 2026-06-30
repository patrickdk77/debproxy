// Package syncer orchestrates ingestion, update jobs, and snapshot publishing.
package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/debversion"
	"github.com/debproxy/debproxy/internal/ingest"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/webhook"
)

// SnapshotIDFormat is the timestamp layout used for snapshot directory names.
const SnapshotIDFormat = "2006-01-02T15-04-05"

// Syncer ties together storage, the index, and the signing key.
type Syncer struct {
	cfg        *config.Config
	store      storage.Storage
	index      metadata.MetadataIndex
	key        *signing.Key
	client     *http.Client
	indexCache *upstream.IndexCache
	notifier   *webhook.Notifier
	exists     *ingest.ExistsCache
}

// New constructs a Syncer. notifier may be nil.
func New(cfg *config.Config, store storage.Storage, index metadata.MetadataIndex, key *signing.Key, client *http.Client, indexCache *upstream.IndexCache, notifier *webhook.Notifier) *Syncer {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if indexCache == nil {
		indexCache = upstream.NewIndexCache()
	}
	return &Syncer{cfg: cfg, store: store, index: index, key: key, client: client, indexCache: indexCache, notifier: notifier, exists: &ingest.ExistsCache{}}
}

// PreloadExistsCache populates the in-memory pool-exists cache from the current
// metadata index so that Cache calls skip redundant storage Exists checks for
// files already known to be present.
func (s *Syncer) PreloadExistsCache(ctx context.Context) error {
	entries, err := s.index.ListEntries(ctx, model.Selector{})
	if err != nil {
		return err
	}
	for _, e := range entries {
		s.exists.Add(e.PoolPath)
	}
	slog.Info("pool exists cache preloaded", "entries", len(entries))
	return nil
}

// codenameSet maps os -> codename -> components -> arches from resolved layouts.
type osCodename struct {
	osName, codename string
}

func (s *Syncer) layoutsByOSCodename() map[osCodename][]model.Layout {
	m := map[osCodename][]model.Layout{}
	for _, l := range s.cfg.ResolvedLayouts {
		k := osCodename{l.OS, l.Codename}
		m[k] = append(m[k], l)
	}
	return m
}

// Prime fetches the dependency closure of the named packages and caches them.
// Intended for seeding a cache and for tests.
func (s *Syncer) Prime(ctx context.Context, osName, codename, component string, names []string) error {
	if err := s.index.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh index: %w", err)
	}
	av := avail.Build(ctx, s.cfg, s.client, s.indexCache, osName, codename)
	in := ingest.New(s.store, s.index, s.client, s.notifier, s.exists)
	for _, arch := range av.Arches {
		closure := av.DepClosure(component, arch, names)
		for _, p := range closure {
			if err := in.Cache(ctx, osName, codename, p); err != nil {
				return fmt.Errorf("cache %s: %w", p.Name, err)
			}
		}
	}
	return nil
}

// Update fetches fresh upstream data and updates any auto_update packages,
// then publishes a new snapshot.
func (s *Syncer) Update(ctx context.Context) error {
	// Use a fresh cache so each manual update does at least a conditional GET
	// against upstream rather than serving a still-fresh entry from the server cache.
	return s.runUpdate(ctx, upstream.NewIndexCache())
}

// UpdateWithCache runs the same update logic as Update but reuses an already-
// populated index cache (e.g. from a background refresh) instead of fetching
// from scratch.
func (s *Syncer) UpdateWithCache(ctx context.Context, cache *upstream.IndexCache) error {
	return s.runUpdate(ctx, cache)
}

func (s *Syncer) runUpdate(ctx context.Context, cache *upstream.IndexCache) error {
	if err := s.index.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh index: %w", err)
	}
	in := ingest.New(s.store, s.index, s.client, s.notifier, s.exists)

	for k := range s.layoutsByOSCodename() {
		av := avail.Build(ctx, s.cfg, s.client, cache, k.osName, k.codename)
		entries, err := s.index.ListEntries(ctx, model.Selector{OS: k.osName, Codename: k.codename})
		if err != nil {
			return err
		}

		updated := 0
		for _, e := range entries {
			compMap := av.Pkgs[e.Component]
			if compMap == nil {
				continue
			}
			archMap := compMap[e.Arch]
			if archMap == nil {
				// arch=all packages are tracked per index arch; try any arch.
				archMap = anyArchWithPkg(compMap, e.Package)
			}
			p, ok := archMap[e.Package]
			if !ok || !p.Upstream.AutoUpdate {
				continue
			}
			if debversion.Compare(p.Version, e.Version) <= 0 {
				continue
			}
			closure := av.DepClosure(e.Component, e.Arch, []string{e.Package})
			for _, dep := range closure {
				if err := in.Cache(ctx, k.osName, k.codename, dep); err != nil {
					return fmt.Errorf("update cache %s: %w", dep.Name, err)
				}
			}
			updated++
			if err := s.index.UpsertUpstreamState(ctx, model.UpstreamPackageState{
				Upstream:        p.Upstream.Name,
				PackageName:     p.Name,
				Arch:            p.Arch,
				UpstreamVersion: p.Version,
				LastChecked:     metadata.Now(),
			}); err != nil {
				slog.Warn("upsert upstream state", "package", p.Name, "err", err)
			}
		}
		slog.Info("update job", "os", k.osName, "codename", k.codename, "updated", updated)
	}

	return s.Snapshot(ctx, time.Now())
}

func anyArchWithPkg(compMap map[string]map[string]avail.Pkg, name string) map[string]avail.Pkg {
	for _, archMap := range compMap {
		if _, ok := archMap[name]; ok {
			return archMap
		}
	}
	return map[string]avail.Pkg{}
}

// Snapshot publishes a signed, immutable snapshot of the current cache state
// for every OS, then points /current at it.
func (s *Syncer) Snapshot(ctx context.Context, now time.Time) error {
	if err := s.index.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh index: %w", err)
	}
	snapshotID := now.UTC().Format(SnapshotIDFormat)

	byOS := map[string][]osCodename{}
	for k := range s.layoutsByOSCodename() {
		byOS[k.osName] = append(byOS[k.osName], k)
	}

	for osName, codenames := range byOS {
		for _, k := range codenames {
			if err := s.publishSuite(ctx, s.store, snapshotID+"/"+osName, k.osName, k.codename, now); err != nil {
				return err
			}
			if err := s.publishSuite(ctx, s.store, "current/"+osName, k.osName, k.codename, now); err != nil {
				return err
			}
		}
		slog.Info("published snapshot", "os", osName, "snapshot", snapshotID)
	}
	return nil
}

// publishSuite writes a single suite's dists tree from cached index entries.
func (s *Syncer) publishSuite(ctx context.Context, sink publish.FileSink, prefix, osName, codename string, now time.Time) error {
	entries, err := s.index.ListEntries(ctx, model.Selector{OS: osName, Codename: codename})
	if err != nil {
		return err
	}
	components, arches := s.componentsAndArches(osName, codename)
	stanzas := groupStanzas(entries, components, arches)

	in := publish.SuiteInput{
		OS:            osName,
		Codename:      codename,
		Suite:         codename,
		Origin:        "debproxy",
		Label:         "debproxy",
		Description:   fmt.Sprintf("debproxy cache of %s/%s", osName, codename),
		Architectures: arches,
		Components:    components,
		Stanzas:       stanzas,
		Date:          now,
	}
	return publish.GenerateSuite(ctx, sink, prefix, in, s.key)
}

func (s *Syncer) componentsAndArches(osName, codename string) ([]string, []string) {
	compSet := map[string]bool{}
	archSet := map[string]bool{}
	for _, l := range s.cfg.ResolvedLayouts {
		if l.OS != osName || l.Codename != codename {
			continue
		}
		compSet[l.Component] = true
		for _, a := range l.Archs {
			archSet[a] = true
		}
	}
	return sortedKeys(compSet), sortedKeys(archSet)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// groupStanzas builds Stanzas[component][arch], fanning Architecture: all
// packages into every binary-arch index per Debian convention.
func groupStanzas(entries []model.IndexEntry, components, arches []string) map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for _, comp := range components {
		out[comp] = map[string][]string{}
		for _, arch := range arches {
			out[comp][arch] = nil
		}
	}
	for _, e := range entries {
		comp := out[e.Component]
		if comp == nil {
			continue
		}
		if e.Arch == "all" {
			for _, arch := range arches {
				comp[arch] = append(comp[arch], e.Control)
			}
			continue
		}
		if _, ok := comp[e.Arch]; ok {
			comp[e.Arch] = append(comp[e.Arch], e.Control)
		}
	}
	return out
}

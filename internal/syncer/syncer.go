// Package syncer orchestrates ingestion, update jobs, and snapshot publishing.
package syncer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/debversion"
	"github.com/debproxy/debproxy/internal/ingest"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/webhook"
)

// SnapshotIDFormat is the timestamp layout used for snapshot directory names.
const SnapshotIDFormat = "2006-01-02T15-04-05"

// currentSnapshotNamePath is the plain-text file written by Snapshot
// recording which snapshot ID "current" points to (see CurrentSnapshotName).
const currentSnapshotNamePath = "current/snapshot-name"

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

// ExistsCache returns the syncer's pool-exists cache so it can be shared with
// the server for consistent pull-through tracking.
func (s *Syncer) ExistsCache() *ingest.ExistsCache { return s.exists }

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
			if err := in.Cache(ctx, osName, codename, p, true); err != nil {
				return fmt.Errorf("cache %s: %w", p.Name, err)
			}
		}
	}
	return nil
}

// Update fetches fresh upstream data and updates any auto_update packages,
// then publishes a new snapshot.
//
// Takes s.indexCache's build lock for the duration of the update, mirroring
// cmd/debproxy's per-layout background refresher (see IndexCache.Lock's own
// doc comment) -- necessary, not just cosmetic, now that this can run
// concurrently with that refresher against the very same shared cache (e.g.
// triggered by POST /api/v1/update while the server is also live): without
// it, the two could build through the cache at the same time, each
// independently holding a Valkey fetch lock and resident merge memory. Safe
// even when indexCache is a private, unshared instance (e.g. the `debproxy
// update` CLI command) -- an uncontended Lock/Unlock is nearly free.
func (s *Syncer) Update(ctx context.Context) error {
	// Expire all entries so this call always re-validates against upstream, but
	// keep the cached archPkgs so FetchIndex can use PDiff when packages change.
	s.indexCache.ExpireAll()
	s.indexCache.Lock()
	defer s.indexCache.Unlock()
	return s.runUpdate(ctx, s.indexCache, nil)
}

// UpdateLayoutWithCache runs the same update logic as Update but reuses an
// already-populated index cache (e.g. from a background refresh) instead of
// fetching from scratch, scoped to a single (os, codename) layout grouping,
// for callers that refresh each layout independently (see cmd/debproxy's
// per-layout refresh scheduler) rather than all of them in one
// pass.
func (s *Syncer) UpdateLayoutWithCache(ctx context.Context, cache *upstream.IndexCache, osName, codename string) error {
	only := osCodename{osName, codename}
	return s.runUpdate(ctx, cache, &only)
}

// runUpdate scans every layout (or, if only is non-nil, just that one) for
// auto_update packages/sources with a newer version available upstream, and
// caches them.
func (s *Syncer) runUpdate(ctx context.Context, cache *upstream.IndexCache, only *osCodename) error {
	if err := s.index.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh index: %w", err)
	}
	in := ingest.New(s.store, s.index, s.client, s.notifier, s.exists)

	for k := range s.layoutsByOSCodename() {
		if only != nil && k != *only {
			continue
		}
		av := avail.Build(ctx, s.cfg, s.client, cache, k.osName, k.codename)

		// Snapshot current source versions only when at least one source has
		// auto_update enabled  -- otherwise the map is unused and the index query wasted.
		hasAutoUpdateSrc := false
		for _, srcMap := range av.Srcs {
			for _, sp := range srcMap {
				if sp.Upstream.AutoUpdate {
					hasAutoUpdateSrc = true
					break
				}
			}
			if hasAutoUpdateSrc {
				break
			}
		}
		var prevSrcVersion map[string]string
		if hasAutoUpdateSrc {
			prevSrcEntries, err := s.index.ListSourceEntries(ctx, model.Selector{OS: k.osName, Codename: k.codename})
			if err != nil {
				return err
			}
			prevSrcVersion = make(map[string]string, len(prevSrcEntries))
			for _, e := range prevSrcEntries {
				if e.FilesDownloaded {
					prevSrcVersion[e.Component+"/"+e.Package] = e.Version
				}
			}
		}
		var srcUpdated int

		// Record source entries from upstream Sources indices.
		for comp, srcMap := range av.Srcs {
			for _, sp := range srcMap {
				files := make([]model.SourceFile, len(sp.Files))
				for i, f := range sp.Files {
					files[i] = model.SourceFile{
						Filename: f.Filename,
						Size:     f.Size,
						SHA256:   model.Digest(f.SHA256),
					}
				}
				entry := model.SourceEntry{
					OS:          k.osName,
					Codename:    k.codename,
					Component:   comp,
					Package:     sp.Package,
					Version:     sp.Version,
					Upstream:    sp.Upstream.Name,
					LocalDir:    sp.LocalDir,
					UpstreamDir: sp.UpstreamDir,
					Files:       files,
					Stanza:      sp.StanzaStr,
				}
				if err := s.index.UpsertSourceEntry(ctx, entry); err != nil {
					slog.Warn("upsert source entry", "package", sp.Package, "version", sp.Version, "err", err)
				}
				if sp.Upstream.AutoUpdate && prevSrcVersion != nil {
					if prevVer, wasSeen := prevSrcVersion[comp+"/"+sp.Package]; wasSeen && debversion.Compare(sp.Version, prevVer) > 0 {
						for _, sf := range files {
							if err := in.CacheSourceFile(ctx, entry, sp.Upstream, sf.Filename); err != nil {
								slog.Warn("auto-update source: cache file",
									"package", sp.Package, "version", sp.Version,
									"file", sf.Filename, "err", err)
							}
						}
						entry.FilesDownloaded = true
						if err := s.index.UpsertSourceEntry(ctx, entry); err != nil {
							slog.Warn("upsert source entry after auto-update download", "package", sp.Package, "err", err)
						}
						srcUpdated++
						// One notification per source package, not per file --
						// its files (.dsc, orig tarball, debian tarball/diff)
						// are all one logical update, mirroring the binary
						// side's one-webhook-per-updated-package rule.
						s.notifier.Fire(webhook.Event{
							Package:   sp.Package,
							Version:   sp.Version,
							OS:        k.osName,
							Codename:  k.codename,
							Component: comp,
							Upstream:  sp.Upstream.Name,
							PoolPath:  sp.LocalDir,
						})
					}
				}
			}
		}
		slog.Info("source update job", "os", k.osName, "codename", k.codename, "updated", srcUpdated)

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
			// Downloading p itself is the notification-worthy event; the rest
			// of the closure is only here to satisfy p's own Depends/
			// Pre-Depends -- those downloads must still happen (an installed
			// dependency requirement, not merely an optional nicety), but
			// they're not separate updates of their own and stay silent.
			closure := av.DepClosure(e.Component, e.Arch, []string{e.Package})
			for _, dep := range closure {
				if err := in.Cache(ctx, k.osName, k.codename, dep, dep.Name == e.Package); err != nil {
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
		debug.FreeOSMemory()
	}

	return nil
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
		metrics.SnapshotPublishesTotal.WithLabelValues(osName).Inc()
	}

	// Write a plain-text file so clients can discover which snapshot ID
	// current points to without parsing Release metadata.
	idBytes := []byte(snapshotID)
	if err := s.store.WriteFile(ctx, currentSnapshotNamePath, strings.NewReader(snapshotID), int64(len(idBytes))); err != nil {
		return fmt.Errorf("write %s: %w", currentSnapshotNamePath, err)
	}
	return nil
}

// CurrentSnapshotName returns the snapshot ID "current" currently points to,
// as written by the most recent successful Snapshot call. Returns an error
// satisfying os.IsNotExist if no snapshot has ever been published.
func (s *Syncer) CurrentSnapshotName(ctx context.Context) (string, error) {
	rc, err := s.store.OpenPublished(ctx, currentSnapshotNamePath)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", currentSnapshotNamePath, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// CurrentSnapshotAge returns how long ago the current snapshot was
// published, relative to now, derived by parsing its ID (a SnapshotIDFormat
// timestamp -- the ID *is* the timestamp, so no separate stored value is
// needed). ok is false (with a nil error) when no snapshot has ever been
// published; used by both the periodic snapshot scheduler and the API's
// non-force snapshot path to implement the snapshot debounce window.
func (s *Syncer) CurrentSnapshotAge(ctx context.Context, now time.Time) (age time.Duration, ok bool, err error) {
	name, err := s.CurrentSnapshotName(ctx)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	t, err := time.Parse(SnapshotIDFormat, name)
	if err != nil {
		return 0, false, fmt.Errorf("parse snapshot id %q: %w", name, err)
	}
	return now.Sub(t), true, nil
}

// publishSuite writes a single suite's dists tree from cached index entries.
func (s *Syncer) publishSuite(ctx context.Context, sink publish.FileSink, prefix, osName, codename string, now time.Time) error {
	entries, err := s.index.ListEntries(ctx, model.Selector{OS: osName, Codename: codename})
	if err != nil {
		return err
	}
	components, arches := s.cfg.ComponentsAndArches(osName, codename)
	stanzas := groupStanzas(entries, components, arches)

	srcEntries, err := s.index.ListSourceEntries(ctx, model.Selector{OS: osName, Codename: codename})
	if err != nil {
		return err
	}
	sourceStanzas := groupSourceStanzas(srcEntries, components)

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
		SourceStanzas: sourceStanzas,
		Date:          now,
		Compression:   s.cfg.Storage.Compression.ResolveSnapshot(),
		HashTypes:     s.cfg.HashTypesFor(osName, codename),
	}
	return publish.GenerateSuite(ctx, sink, prefix, in, s.key)
}

// highestVersionByKey groups items by key and keeps only the one with the
// highest Version per key. Used wherever superseded package versions must be
// excluded: publishing (groupStanzas, groupSourceStanzas) and pool/src GC
// reference-set building (buildPoolRefSet, buildSrcRefSet in cleanup.go).
func highestVersionByKey[K comparable, T any](items []T, keyOf func(T) K, versionOf func(T) string) map[K]T {
	best := make(map[K]T, len(items))
	for _, item := range items {
		k := keyOf(item)
		if existing, ok := best[k]; !ok || debversion.Compare(versionOf(item), versionOf(existing)) > 0 {
			best[k] = item
		}
	}
	return best
}

// groupSourceStanzas builds SourceStanzas[component] from source entries.
// When the metadata holds multiple versions of the same source package, only
// the highest version is included in the snapshot.
// Returns nil when there are no source entries at all.
func groupSourceStanzas(entries []model.SourceEntry, components []string) map[string][]string {
	if len(entries) == 0 {
		return nil
	}
	type key struct{ comp, pkg string }
	best := highestVersionByKey(entries,
		func(e model.SourceEntry) key { return key{e.Component, e.Package} },
		func(e model.SourceEntry) string { return e.Version })
	out := map[string][]string{}
	for _, comp := range components {
		out[comp] = nil
	}
	for k, e := range best {
		if _, ok := out[k.comp]; ok {
			out[k.comp] = append(out[k.comp], e.Stanza)
		}
	}
	return out
}

// groupStanzas builds Stanzas[component][arch], fanning Architecture: all
// packages into every binary-arch index per Debian convention.
// When the metadata holds multiple versions of the same package (e.g. after an
// auto_update download), only the highest version is included in the snapshot.
func groupStanzas(entries []model.IndexEntry, components, arches []string) map[string]map[string][]string {
	// Phase 1: for each (component, arch, package) keep only the highest version.
	type key struct{ comp, arch, pkg string }
	best := highestVersionByKey(entries,
		func(e model.IndexEntry) key { return key{e.Component, e.Arch, e.Package} },
		func(e model.IndexEntry) string { return e.Version })

	// Phase 2: build output, fanning arch=all into every arch.
	out := map[string]map[string][]string{}
	for _, comp := range components {
		out[comp] = map[string][]string{}
		for _, arch := range arches {
			out[comp][arch] = nil
		}
	}
	for k, e := range best {
		comp := out[k.comp]
		if comp == nil {
			continue
		}
		if k.arch == "all" {
			for _, arch := range arches {
				comp[arch] = append(comp[arch], e.Control)
			}
		} else if _, ok := comp[k.arch]; ok {
			comp[k.arch] = append(comp[k.arch], e.Control)
		}
	}
	return out
}

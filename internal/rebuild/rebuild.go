package rebuild

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/deb"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
)

// Options configures a rebuild run.
type Options struct {
	ResetIndex bool
	// HTTPClient is used to fetch upstream Packages files on demand when a pool
	// file has no prior index entry. If nil, such files fall back to being
	// indexed under all upstream components (with a warning).
	HTTPClient *http.Client
}

// Run scans the pool and repopulates the metadata index from .deb control data.
// Component membership is resolved in order:
//  1. Existing index entries (read before any reset)  -- authoritative.
//  2. Upstream Packages fetched on demand via HTTPClient  -- for files missing from index.
//  3. All upstream components with a warning  -- last resort when offline.
func Run(ctx context.Context, cfg *config.Config, store storage.Storage, index metadata.MetadataIndex, opts Options) error {
	poolComponents, err := buildPoolComponentMap(ctx, index)
	if err != nil {
		return fmt.Errorf("read existing index: %w", err)
	}

	if opts.ResetIndex {
		if err := index.Reset(ctx); err != nil {
			return fmt.Errorf("reset index: %w", err)
		}
	}

	upstreamComponents := buildUpstreamComponentMap(cfg)
	fetcher := newLazyFetcher(cfg, opts.HTTPClient)

	var files, entries int
	err = store.WalkPool(ctx, func(poolPath string) error {
		rc, err := store.Open(ctx, poolPath)
		if err != nil {
			return err
		}
		rs, cleanup, err := toReadSeeker(rc)
		if err != nil {
			return err
		}
		defer cleanup()

		ctrl, err := deb.ControlParagraph(rs)
		if err != nil {
			slog.Warn("skip deb", "path", poolPath, "err", err)
			return nil
		}

		checksums, err := store.ComputeChecksums(ctx, poolPath)
		if err != nil {
			return err
		}
		info, err := store.Stat(ctx, poolPath)
		if err != nil {
			return err
		}

		osName, codename, upstreamName := parsePoolPath(poolPath)
		stanza := apt.BuildPackagesStanza(ctrl, poolPath, info.Size,
			checksums.SHA256.String(), checksums.SHA512.String())
		control, err := apt.StanzaString(stanza)
		if err != nil {
			return err
		}
		pkgName := ctrl.Get("Package")
		pkgVersion := ctrl.Get("Version")
		pkgArch := ctrl.Get("Architecture")

		comps, ok := poolComponents[poolPath]
		if !ok {
			// Not in prior index  -- ask upstream Packages (fetched on demand).
			comps, ok = fetcher.lookup(ctx, osName, codename, upstreamName, pkgName, pkgVersion, pkgArch)
		}
		if !ok {
			key := upstreamKey{osName, codename, upstreamName}
			allComps := upstreamComponents[key]
			if len(allComps) == 0 {
				comps = []componentRef{{component: "", autoUpdate: false}}
			} else {
				slog.Warn("component unknown, indexing under all upstream components",
					"path", poolPath, "components", len(allComps))
				comps = allComps
			}
		}

		files++
		for _, comp := range comps {
			entry := model.IndexEntry{
				OS:             osName,
				Codename:       codename,
				Component:      comp.component,
				Arch:           pkgArch,
				Package:        pkgName,
				Version:        pkgVersion,
				Upstream:       upstreamName,
				FromAutoUpdate: comp.autoUpdate,
				PoolPath:       poolPath,
				Checksums:      checksums,
				Size:           info.Size,
				Control:        control,
				FirstSeen:      metadata.Now(),
			}
			if err := index.UpsertEntry(ctx, entry); err != nil {
				return err
			}
			entries++
		}
		return nil
	})
	if err != nil {
		return err
	}
	slog.Info("rebuild complete", "pool_files", files, "index_entries", entries)
	return nil
}

// lazyFetcher fetches upstream Packages only for upstreams that have files
// not covered by the prior index, caching results across multiple lookups.
type lazyFetcher struct {
	cfg     *config.Config
	client  *http.Client
	fetched map[lazyFetchKey]bool
	m       map[upstreamPkgKey][]componentRef
}

type lazyFetchKey struct{ url, suite, component string }

func newLazyFetcher(cfg *config.Config, client *http.Client) *lazyFetcher {
	return &lazyFetcher{
		cfg:     cfg,
		client:  client,
		fetched: map[lazyFetchKey]bool{},
		m:       map[upstreamPkgKey][]componentRef{},
	}
}

// lookup resolves component for the given file, fetching the relevant upstream
// Packages on demand if needed and not already cached.
func (lf *lazyFetcher) lookup(ctx context.Context, osName, codename, upstreamName, pkgName, version, arch string) ([]componentRef, bool) {
	if lf.client == nil {
		return nil, false
	}
	lf.ensureFetched(ctx, osName, codename, upstreamName)
	comps, ok := lf.m[upstreamPkgKey{upstreamName, pkgName, version, arch}]
	return comps, ok
}

// ensureFetched fetches all component Packages for upstreamName in the given
// os/codename if they haven't been fetched yet.
func (lf *lazyFetcher) ensureFetched(ctx context.Context, osName, codename, upstreamName string) {
	for _, layout := range lf.cfg.ResolvedLayouts {
		if layout.OS != osName || layout.Codename != codename {
			continue
		}
		for _, src := range layout.Upstreams {
			if src.Name != upstreamName {
				continue
			}
			fk := lazyFetchKey{src.URL, src.Suite, src.Component}
			if lf.fetched[fk] {
				continue
			}
			lf.fetched[fk] = true

			slog.Info("fetching upstream packages", "upstream", src.Name, "component", src.Component)
			f := upstream.NewFetcher(src, lf.client)
			idx, err := f.FetchIndex(ctx)
			if err != nil {
				slog.Warn("fetch upstream index", "upstream", src.Name, "component", src.Component, "err", err)
				continue
			}
			comp := componentRef{component: layout.Component, autoUpdate: src.AutoUpdate}
			for _, stanzas := range idx.ByArch {
				for _, st := range stanzas {
					name := st.Package
					ver := st.Version
					a := st.Arch
					if name == "" || ver == "" || a == "" {
						continue
					}
					pk := upstreamPkgKey{src.Name, name, ver, a}
					alreadyHas := false
					for _, existing := range lf.m[pk] {
						if existing.component == comp.component {
							alreadyHas = true
							break
						}
					}
					if !alreadyHas {
						lf.m[pk] = append(lf.m[pk], comp)
					}
				}
			}
		}
	}
}

// buildPoolComponentMap reads all existing index entries and returns a map from
// pool path to the list of components that path is indexed under.
func buildPoolComponentMap(ctx context.Context, index metadata.MetadataIndex) (map[string][]componentRef, error) {
	entries, err := index.ListEntries(ctx, model.Selector{})
	if err != nil {
		return nil, err
	}
	m := make(map[string][]componentRef, len(entries))
	for _, e := range entries {
		m[e.PoolPath] = append(m[e.PoolPath], componentRef{
			component:  e.Component,
			autoUpdate: e.FromAutoUpdate,
		})
	}
	return m, nil
}

type upstreamKey struct {
	osName, codename, upstream string
}

type componentRef struct {
	component  string
	autoUpdate bool
}

type upstreamPkgKey struct {
	upstream, pkg, version, arch string
}

func buildUpstreamComponentMap(cfg *config.Config) map[upstreamKey][]componentRef {
	m := map[upstreamKey][]componentRef{}
	for _, layout := range cfg.ResolvedLayouts {
		for _, up := range layout.Upstreams {
			k := upstreamKey{layout.OS, layout.Codename, up.Name}
			m[k] = append(m[k], componentRef{component: layout.Component, autoUpdate: up.AutoUpdate})
		}
	}
	return m
}

// parsePoolPath extracts os, codename, upstream from pool/{os}/{codename}/{upstream}/...
func parsePoolPath(poolPath string) (osName, codename, upstream string) {
	parts := strings.Split(poolPath, "/")
	if len(parts) >= 4 && parts[0] == "pool" {
		return parts[1], parts[2], parts[3]
	}
	return "", "", ""
}

func toReadSeeker(rc io.ReadCloser) (io.ReadSeeker, func(), error) {
	if rs, ok := rc.(io.ReadSeeker); ok {
		return rs, func() {
			if err := rc.Close(); err != nil {
				slog.Warn("close deb", "err", err)
			}
		}, nil
	}
	data, err := io.ReadAll(rc)
	if cerr := rc.Close(); cerr != nil {
		slog.Warn("close deb", "err", cerr)
	}
	if err != nil {
		return nil, func() {}, err
	}
	return bytes.NewReader(data), func() {}, nil
}

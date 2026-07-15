// Package avail builds the merged "available" view of a codename by fetching
// and merging the verified upstream Packages indices referenced by the layout.
package avail

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/debversion"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/upstream"
)

// Pkg is one available package version selected for a (component, arch).
type Pkg struct {
	Name       string
	Version    string
	Arch       string
	Section    string
	Component  string
	Filename   string // upstream-relative path
	SHA256     string
	SHA512     string
	Size       int64
	PoolPath   string
	Depends    string
	PreDepends string
	Upstream   model.UpstreamSource
	StanzaStr  string // verbatim upstream stanza with Filename rewritten to PoolPath
}

// SrcPkg is one source package version selected for a component.
type SrcPkg struct {
	Package     string
	Version     string
	Component   string
	UpstreamDir string // upstream's original Directory: field (for pull-through)
	LocalDir    string // our src/ storage directory
	Files       []apt.RawSrcFile
	Upstream    model.UpstreamSource
	StanzaStr   string // Sources stanza with Directory: rewritten to LocalDir
}

// Available is the merged view for one os/codename across all its components.
type Available struct {
	OS               string
	Codename         string
	Components       []string
	Arches           []string
	HasStaleMismatch bool // true if any upstream fell back to stale due to a digest mismatch
	// Pkgs[component][arch][name] = selected package.
	Pkgs       map[string]map[string]map[string]Pkg
	ByPoolPath map[string]Pkg
	// Srcs[component][name] = selected source package. Only populated when at
	// least one upstream in the layout has FetchSources set.
	Srcs map[string]map[string]SrcPkg
}

// upstreamResult holds the parsed index for one upstream source within a layout.
type upstreamResult struct {
	component string
	src       model.UpstreamSource
	idx       *upstream.Index
}

// Build fetches and merges all upstreams for every component of os/codename.
// Upstreams are fetched concurrently. cache may be nil (disables HTTP caching).
func Build(ctx context.Context, cfg *config.Config, client *http.Client, cache *upstream.IndexCache, osName, codename string) *Available {
	av := &Available{
		OS:         osName,
		Codename:   codename,
		Pkgs:       map[string]map[string]map[string]Pkg{},
		ByPoolPath: map[string]Pkg{},
	}
	archSet := map[string]bool{}

	// Collect layouts for this os/codename and initialise component maps.
	type work struct {
		component string
		src       model.UpstreamSource
	}
	var jobs []work
	for _, layout := range cfg.ResolvedLayouts {
		if layout.OS != osName || layout.Codename != codename {
			continue
		}
		if _, seen := av.Pkgs[layout.Component]; !seen {
			av.Components = append(av.Components, layout.Component)
			av.Pkgs[layout.Component] = map[string]map[string]Pkg{}
		}
		for _, a := range layout.Archs {
			if a != "all" {
				archSet[a] = true
			}
		}
		for _, src := range layout.Upstreams {
			jobs = append(jobs, work{layout.Component, src})
		}
	}

	// If some replica already established this layout as fresh within the
	// last schedule.refresh interval (see upstream.IndexCache.LayoutDataFresh),
	// trust Valkey's published data outright for every upstream feeding it,
	// rather than gating each one on its own Cache-Control-derived Expires
	// (which mirrors that send no caching headers default to a bare 5
	// minutes -- far shorter than any real refresh interval, and would
	// otherwise force a real upstream touch on nearly every call). One
	// Valkey check for the whole layout, not per upstream.
	layoutDataFresh := cache != nil && cache.LayoutDataFresh(ctx, osName, codename)
	refreshInterval := cfg.Schedule.RefreshInterval()
	// didRealFetch/realFetchFailed track every upstream job that didn't take
	// the outright-adopt shortcut (Index and Sources alike -- see below).
	// Marking the layout fresh at the end requires at least one such
	// validation AND zero failures among them: one upstream's real fetch
	// succeeding must never paper over a different upstream's real fetch
	// failing, or that second upstream's stale data could keep getting
	// served indefinitely, propped up by its siblings' successes re-marking
	// the layout fresh every cycle without ever giving it a real recheck.
	var didRealFetch, realFetchFailed atomic.Bool

	// Fetch all upstreams concurrently.
	results := make([]upstreamResult, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j work) {
			defer wg.Done()
			f := upstream.NewFetcherWithCache(j.src, client, cache)
			var idx *upstream.Index
			if layoutDataFresh {
				idx, _ = f.AdoptFromValkeyOutright(ctx)
			}
			if idx != nil {
				slog.Debug("upstream index adopted from valkey outright", "upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component)
			} else {
				slog.Debug("upstream index outright-adopt miss, falling through to normal fetch path", "upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component, "layout_data_fresh", layoutDataFresh)
				var err error
				idx, err = f.FetchIndex(ctx)
				if err != nil {
					slog.Error("upstream index unavailable, skipping", "upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component, "err", err)
					realFetchFailed.Store(true)
					return
				}
				didRealFetch.Store(true)
			}
			var total int
			for _, stanzas := range idx.ByArch {
				total += len(stanzas)
			}
			slog.Debug("fetched upstream index", "upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component, "packages", total)
			results[i] = upstreamResult{component: j.component, src: j.src, idx: idx}
		}(i, j)
	}
	wg.Wait()

	// Phase 1: run buildPkg for each (result, arch) pair in parallel.
	// Each goroutine builds its own private map  -- no concurrent writes to shared state.
	type archEntry struct {
		component string
		arch      string
		pkgs      map[string]Pkg
		stale     bool
	}
	nPairs := 0
	for _, r := range results {
		if r.idx != nil {
			nPairs += len(r.idx.ByArch)
		}
	}
	entries := make([]archEntry, 0, nPairs)
	var entMu sync.Mutex
	var wg2 sync.WaitGroup
	for _, r := range results {
		if r.idx == nil {
			continue
		}
		for arch, stanzas := range r.idx.ByArch {
			wg2.Add(1)
			r2, arch2, stanzas2 := r, arch, stanzas
			go func() {
				defer wg2.Done()
				dest := make(map[string]Pkg, len(stanzas2))
				for _, st := range stanzas2 {
					p := buildPkg(osName, codename, r2.component, arch2, r2.src, st)
					if p.Name == "" {
						continue
					}
					if existing, ok := dest[p.Name]; ok && debversion.Compare(p.Version, existing.Version) <= 0 {
						continue
					}
					dest[p.Name] = p
				}
				entMu.Lock()
				entries = append(entries, archEntry{r2.component, arch2, dest, r2.idx.HasStaleMismatch})
				entMu.Unlock()
			}()
		}
	}
	wg2.Wait()

	// Phase 2a: merge binary-arch results. Must run before Phase 2b so the
	// per-arch maps are initialized before arch=all packages are fanned into them.
	for _, e := range entries {
		if e.arch == "all" {
			continue
		}
		if e.stale {
			av.HasStaleMismatch = true
		}
		dest := av.Pkgs[e.component][e.arch]
		if dest == nil {
			dest = make(map[string]Pkg, len(e.pkgs))
			av.Pkgs[e.component][e.arch] = dest
		}
		for name, p := range e.pkgs {
			if existing, ok := dest[name]; ok && debversion.Compare(p.Version, existing.Version) <= 0 {
				continue
			}
			dest[name] = p
			av.ByPoolPath[p.PoolPath] = p
		}
	}

	// Phase 2b: fan arch=all packages into every binary arch we serve.
	// These come from upstreams that publish a separate binary-all/Packages
	// (e.g. Debian main) and may include packages absent from the per-arch files.
	for _, e := range entries {
		if e.arch != "all" {
			continue
		}
		if e.stale {
			av.HasStaleMismatch = true
		}
		for _, dest := range av.Pkgs[e.component] {
			for name, p := range e.pkgs {
				if existing, ok := dest[name]; ok && debversion.Compare(p.Version, existing.Version) <= 0 {
					continue
				}
				dest[name] = p
				av.ByPoolPath[p.PoolPath] = p
			}
		}
	}

	for a := range archSet {
		av.Arches = append(av.Arches, a)
	}

	// Fetch Sources indices for upstreams with FetchSources enabled.
	type srcWork struct {
		component string
		src       model.UpstreamSource
	}
	var srcJobs []srcWork
	for _, layout := range cfg.ResolvedLayouts {
		if layout.OS != osName || layout.Codename != codename {
			continue
		}
		for _, src := range layout.Upstreams {
			if src.FetchSources {
				srcJobs = append(srcJobs, srcWork{layout.Component, src})
			}
		}
	}

	if len(srcJobs) > 0 {
		av.Srcs = map[string]map[string]SrcPkg{}
		type srcResult struct {
			component string
			src       model.UpstreamSource
			raws      []apt.RawSrc
		}
		srcResults := make([]srcResult, len(srcJobs))
		var srcWg sync.WaitGroup
		for i, j := range srcJobs {
			srcWg.Add(1)
			go func(i int, j srcWork) {
				defer srcWg.Done()
				f := upstream.NewFetcherWithCache(j.src, client, cache)
				var raws []apt.RawSrc
				if layoutDataFresh {
					raws, _ = f.AdoptSourcesFromValkeyOutright(ctx)
				}
				if raws != nil {
					slog.Debug("upstream Sources adopted from valkey outright", "upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component)
				} else {
					slog.Debug("upstream Sources outright-adopt miss, falling through to normal fetch path", "upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component, "layout_data_fresh", layoutDataFresh)
					var err error
					raws, err = f.FetchSources(ctx)
					if err != nil {
						slog.Warn("upstream Sources unavailable, skipping",
							"upstream", j.src.Name, "suite", j.src.Suite, "component", j.src.Component, "err", err)
						realFetchFailed.Store(true)
						return
					}
					didRealFetch.Store(true)
				}
				slog.Debug("fetched upstream Sources", "upstream", j.src.Name, "component", j.src.Component, "packages", len(raws))
				srcResults[i] = srcResult{j.component, j.src, raws}
			}(i, j)
		}
		srcWg.Wait()

		for _, r := range srcResults {
			if r.raws == nil {
				continue
			}
			if av.Srcs[r.component] == nil {
				av.Srcs[r.component] = map[string]SrcPkg{}
			}
			for _, raw := range r.raws {
				if raw.Package == "" || raw.Version == "" {
					continue
				}
				if existing, ok := av.Srcs[r.component][raw.Package]; ok {
					if strings.Compare(raw.Version, existing.Version) <= 0 {
						continue
					}
				}
				localDir := model.SourceDir(osName, codename, r.src.Name, r.component, raw.Package)
				files := make([]apt.RawSrcFile, len(raw.Files))
				copy(files, raw.Files)
				av.Srcs[r.component][raw.Package] = SrcPkg{
					Package:     raw.Package,
					Version:     raw.Version,
					Component:   r.component,
					UpstreamDir: raw.Directory,
					LocalDir:    localDir,
					Files:       files,
					Upstream:    r.src,
					StanzaStr:   raw.WithDirectory(localDir),
				}
			}
		}
	}

	// Now that every upstream's data has been merged into av, evict it from
	// the shared local cache -- a no-op unless cache is Valkey-backed (see
	// IndexCache.EvictUpstream), in which case Valkey remains the durable
	// copy and the next Build call (whether the periodic refresher's own
	// cycle or a /live rebuild triggered independently by a client request --
	// both call Build, on entirely different schedules, through this same
	// shared cache) re-adopts a fresh or comparison-only copy from it instead
	// of every layout's fetched Packages/Sources staying resident between
	// every caller's use of it for as long as the process runs.
	if cache != nil {
		evicted := map[string]bool{}
		for _, j := range jobs {
			k := j.src.DedupKey()
			if evicted[k] {
				continue
			}
			evicted[k] = true
			f := upstream.NewFetcher(j.src, nil)
			cache.EvictUpstream(f.InReleaseURL(), f.Component())
		}
		// Only mark the layout fresh if at least one real fetch happened this
		// call AND none of them failed -- if every upstream was itself
		// adopted outright, extending the window would let trust drift
		// forever without ever checking upstream again (see
		// IndexCache.MarkLayoutDataFresh's own doc comment); if even one
		// upstream's real fetch failed, marking fresh anyway would let that
		// one upstream's stale data ride indefinitely on its siblings'
		// success, since every subsequent call would adopt it outright too
		// without ever giving it its own chance to recheck upstream.
		if didRealFetch.Load() && !realFetchFailed.Load() {
			cache.MarkLayoutDataFresh(ctx, osName, codename, refreshInterval)
		}
	}

	return av
}

// ResolvePoolPath re-resolves a single pool path directly against the one
// upstream it names, without needing the layout's whole merged Available
// view to already have it. poolPath itself already encodes enough to
// identify exactly which upstream to check (see model.PoolPath) -- os,
// codename, and upstream name are all path segments -- so a package this
// replica's last layout-wide rebuild happened to miss (a slow/degraded
// rebuild, a transient read failure for one upstream) shouldn't be rejected
// outright when the real, current data is one upstream-scoped check away.
// Used as servePool's fallback when the live path's own av doesn't have
// poolPath: this is a live request path, so this only ever checks the one
// named upstream (via the same Valkey-outright-adopt/real-fetch path Build
// itself uses for that upstream), never the whole layout.
//
// Returns an error if poolPath doesn't parse, no configured upstream in
// osName/codename has this name, or that upstream's current data doesn't
// contain a package at exactly this pool path.
func ResolvePoolPath(ctx context.Context, cfg *config.Config, client *http.Client, cache *upstream.IndexCache, osName, codename, poolPath string) (Pkg, error) {
	upstreamName, ok := upstreamNameFromPoolPath(poolPath)
	if !ok {
		return Pkg{}, fmt.Errorf("invalid pool path %q", poolPath)
	}

	// Never trust cache's own local entries here: this fallback only runs
	// after the live av already missed, and cache is typically the very
	// same IndexCache that produced that av -- reusing its local state as-is
	// would just hand back the same stale-or-incomplete answer. See
	// WithoutLocalState's doc comment.
	fresh := cache.WithoutLocalState()

	for _, layout := range cfg.ResolvedLayouts {
		if layout.OS != osName || layout.Codename != codename {
			continue
		}
		for _, src := range layout.Upstreams {
			if src.Name != upstreamName {
				continue
			}
			if p, ok := resolveFromUpstream(ctx, client, fresh, osName, codename, layout.Component, src, poolPath); ok {
				return p, nil
			}
		}
	}
	return Pkg{}, fmt.Errorf("package not available upstream")
}

// upstreamNameFromPoolPath extracts the upstream name segment from a pool
// path of the form pool/{os}/{codename}/{upstream}/... (see model.PoolPath).
func upstreamNameFromPoolPath(poolPath string) (string, bool) {
	segs := strings.SplitN(poolPath, "/", 5)
	if len(segs) < 4 || segs[0] != "pool" {
		return "", false
	}
	return segs[3], true
}

// resolveFromUpstream fetches src's current index (Valkey-outright-adopt
// first, falling through to a real fetch, exactly like Build's own per-
// upstream job) and looks for a package whose derived pool path matches
// poolPath exactly. A large upstream (e.g. universe) means this is a linear
// scan over everything currently known for it, but this path only runs on a
// live-index cache miss -- rare by construction -- so that cost is
// acceptable against the alternative of rejecting a real, available package.
func resolveFromUpstream(ctx context.Context, client *http.Client, cache *upstream.IndexCache, osName, codename, component string, src model.UpstreamSource, poolPath string) (Pkg, bool) {
	f := upstream.NewFetcherWithCache(src, client, cache)
	idx, ok := f.AdoptFromValkeyOutright(ctx)
	if !ok {
		var err error
		idx, err = f.FetchIndex(ctx)
		if err != nil {
			slog.Warn("resolvePoolPath: upstream index unavailable", "upstream", src.Name, "err", err)
			return Pkg{}, false
		}
	}
	for arch, stanzas := range idx.ByArch {
		for _, st := range stanzas {
			p := buildPkg(osName, codename, component, arch, src, st)
			if p.PoolPath == poolPath {
				return p, true
			}
		}
	}
	return Pkg{}, false
}

func buildPkg(osName, codename, component, arch string, src model.UpstreamSource, st apt.RawPkg) Pkg {
	if st.Package == "" || st.Version == "" {
		return Pkg{}
	}
	pkgArch := st.Arch
	if pkgArch == "" {
		pkgArch = arch
	}
	poolPath := poolPathFromFilename(osName, codename, src.Name, st.Section, st.Package, st.Filename)
	return Pkg{
		Name:       st.Package,
		Version:    st.Version,
		Arch:       pkgArch,
		Section:    st.Section,
		Component:  component,
		Filename:   st.Filename,
		SHA256:     st.SHA256,
		SHA512:     st.SHA512,
		Size:       st.Size,
		PoolPath:   poolPath,
		Depends:    st.Depends,
		PreDepends: st.PreDepends,
		Upstream:   src,
		StanzaStr:  st.WithFilename(poolPath),
	}
}

// DepClosure returns the transitive dependency closure (within the available
// set) of the seed package names, including the seeds themselves.
func (av *Available) DepClosure(component, arch string, seeds []string) []Pkg {
	resolved := map[string]Pkg{}
	var queue []string
	queue = append(queue, seeds...)

	lookup := func(name string) (Pkg, bool) {
		if compMap := av.Pkgs[component]; compMap != nil {
			if archMap := compMap[arch]; archMap != nil {
				if p, ok := archMap[name]; ok {
					return p, true
				}
			}
		}
		// Fall back to any component for the given arch.
		for _, compMap := range av.Pkgs {
			if archMap := compMap[arch]; archMap != nil {
				if p, ok := archMap[name]; ok {
					return p, true
				}
			}
		}
		return Pkg{}, false
	}

	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if _, done := resolved[name]; done {
			continue
		}
		p, ok := lookup(name)
		if !ok {
			continue
		}
		resolved[name] = p
		for _, groups := range [][][]string{
			apt.ParseDependencyGroups(p.PreDepends),
			apt.ParseDependencyGroups(p.Depends),
		} {
			for _, alts := range groups {
				for _, alt := range alts {
					if _, ok := lookup(alt); ok {
						queue = append(queue, alt)
						break
					}
				}
			}
		}
	}

	out := make([]Pkg, 0, len(resolved))
	for _, p := range resolved {
		out = append(out, p)
	}
	return out
}

// poolPathFromFilename builds our pool path using our own directory structure
// (section/first/name/) with the actual .deb filename from the upstream.
// Taking only the last component of upstreamFilename means this works regardless
// of how deeply or shallowly the upstream organises its pool.
func poolPathFromFilename(os, codename, upstreamName, section, pkgName, upstreamFilename string) string {
	debFile := upstreamFilename
	if i := strings.LastIndexByte(upstreamFilename, '/'); i >= 0 {
		debFile = upstreamFilename[i+1:]
	}
	first := "_"
	if pkgName != "" {
		first = strings.ToLower(pkgName[:1])
	}
	return "pool/" + os + "/" + codename + "/" + upstreamName + "/" + section + "/" + first + "/" + pkgName + "/" + debFile
}

func parseInt64(s string) int64 {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int64(r-'0')
	}
	return n
}

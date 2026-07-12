// Package upstream fetches and verifies Debian repository metadata and packages
// from configured upstream sources.
package upstream

import (
	"bytes"
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
)

// Fetcher retrieves and verifies content from a single upstream source.
type Fetcher struct {
	src    model.UpstreamSource
	client *http.Client
	cache  *IndexCache // optional; nil disables caching
}

// NewFetcher creates a fetcher for src.
func NewFetcher(src model.UpstreamSource, client *http.Client) *Fetcher {
	return NewFetcherWithCache(src, client, nil)
}

// NewFetcherWithCache creates a fetcher that uses cache for upstream index data.
func NewFetcherWithCache(src model.UpstreamSource, client *http.Client, cache *IndexCache) *Fetcher {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Fetcher{src: src, client: client, cache: cache}
}

// Index is the verified, parsed upstream metadata for a suite.
type Index struct {
	Release          *apt.Release
	ByArch           map[string][]apt.RawPkg
	HasStaleMismatch bool // true if any arch fell back to stale due to a digest mismatch
}

func (f *Fetcher) base() string {
	return strings.TrimRight(f.src.URL, "/")
}

func (f *Fetcher) distsURL(rel string) string {
	return fmt.Sprintf("%s/dists/%s/%s", f.base(), f.src.Suite, rel)
}

// InReleaseURL returns the InRelease URL this fetcher's cache entry is keyed
// by (paired with f.src.Component) -- exported so a caller holding the
// *Fetcher, rather than the raw model.UpstreamSource, can evict this entry
// once done with it (see IndexCache.EvictUpstream) without duplicating this
// URL construction itself.
func (f *Fetcher) InReleaseURL() string {
	return f.distsURL("InRelease")
}

// cacheKey is the IndexCache key for this fetcher's upstream+suite+
// component -- the single source of this formula so FetchIndex,
// FetchSources, and the AdoptFromValkeyOutright family never drift apart.
func (f *Fetcher) cacheKey() string {
	return f.InReleaseURL() + "\x00" + f.src.Component
}

// Component returns the configured component this fetcher's upstream source
// belongs to (paired with InReleaseURL to form a cache key -- see
// IndexCache.EvictUpstream).
func (f *Fetcher) Component() string {
	return f.src.Component
}

// acquireByHash reports whether the upstream release advertises by-hash index
// downloads (Acquire-By-Hash: yes in InRelease/Release).
func acquireByHash(rel *apt.Release) bool {
	return strings.EqualFold(rel.Get("Acquire-By-Hash"), "yes")
}

// indexURL returns the URL to use for fetching an index file.
// When byHash is true and sha256 is non-empty it returns the by-hash path
// ({dir}/by-hash/SHA256/{sha256}), otherwise the conventional dists path.
func (f *Fetcher) indexURL(relPath, sha256 string, byHash bool) string {
	if byHash && sha256 != "" {
		dir := relPath[:strings.LastIndexByte(relPath, '/')+1]
		return f.distsURL(dir + "by-hash/SHA256/" + sha256)
	}
	return f.distsURL(relPath)
}

// releaseServedArchs returns the subset of srcArchs (plus "all", if served)
// that rel actually lists a Packages file for under component -- the
// authoritative way to know which architectures an upstream serves, used by
// both FetchIndex (to decide what to fetch) and AdoptFromValkeyOutright (to
// tell "not yet confirmed" apart from "confirmed to serve nothing"). The
// Architectures field itself is not used: upstreams like archive.ubuntu.com
// list every architecture there even though arm64 Packages are only served
// from ports.ubuntu.com. Checking rel.Files is authoritative: if no Packages
// variant is listed for a given arch, the upstream does not serve it -- and
// that fact never changes for a given (immutable, digest-addressed) Release,
// so it's safe to trust from a cached copy without re-fetching to confirm.
func releaseServedArchs(rel *apt.Release, component string, srcArchs []string) []string {
	archs := make([]string, 0, len(srcArchs)+1)
	for _, arch := range srcArchs {
		prefix := component + "/binary-" + arch + "/Packages"
		for path := range rel.Files {
			if strings.HasPrefix(path, prefix) {
				archs = append(archs, arch)
				break
			}
		}
	}
	// Always include binary-all/Packages when the upstream serves it,
	// regardless of configured architectures. avail.Build fans these
	// packages into every binary arch index, capturing packages that only
	// appear in the dedicated all-packages file (e.g. some Debian packages
	// absent from per-arch Packages files).
	allPrefix := component + "/binary-all/Packages"
	for path := range rel.Files {
		if strings.HasPrefix(path, allPrefix) {
			archs = append(archs, "all")
			break
		}
	}
	return archs
}

// releaseListsSources reports whether rel lists any Sources file variant
// under component -- the same file-existence check fetchSourcesFile makes
// before ever issuing a request, so a cached Release can confirm "this
// upstream/component has no Sources at all" without a network round trip,
// the Sources counterpart to releaseServedArchs.
func releaseListsSources(rel *apt.Release, component string) bool {
	base := component + "/source/"
	for _, v := range srcVariants {
		if _, ok := rel.Files[base+v.ext]; ok {
			return true
		}
	}
	return false
}

// fastFallbackTimeout bounds a single fetch attempt when a stale-but-usable
// comparison entry is already in hand (see cachedForComparison/
// srcsCachedForComparison) -- rather than waiting through NewHTTPClient's
// full retry budget (up to ~4 attempts x 30s ResponseHeaderTimeout each, plus
// escalating delays -- worst case around two minutes) against a mirror
// that's currently slow or down, a bad upstream degrades to "serve what we
// already have" in seconds instead of stalling an entire avail.Build (and so
// a whole /live rebuild) for that long. retryTransport treats context
// cancellation as non-retryable, so this cleanly aborts after one bounded
// attempt rather than exhausting retries first. Only applied when a fallback
// actually exists: with nothing to fall back to, the full retry budget is
// worth spending for a real answer instead of failing the fetch outright.
const fastFallbackTimeout = 5 * time.Second

// withFallbackTimeout returns ctx bounded by fastFallbackTimeout when
// haveFallback is true, and ctx unchanged (with a no-op cancel) otherwise.
func withFallbackTimeout(ctx context.Context, haveFallback bool) (context.Context, context.CancelFunc) {
	if !haveFallback {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, fastFallbackTimeout)
}

// FetchIndex downloads, signature-verifies, and parses the suite Release plus
// the Packages indices for the configured component and architectures.
// When a cache is configured it sends conditional requests (ETag/304) and
// reuses previously-parsed Packages data if the Release hash is unchanged.
func (f *Fetcher) FetchIndex(ctx context.Context) (*Index, error) {
	// The cache key includes the component because the same upstream URL+suite
	// may be used across multiple component layouts (e.g. ubuntu-main is listed
	// in main, universe, restricted, and multiverse). Without the component, the
	// first layout's Packages data would be returned for all others.
	cacheKey := f.cacheKey()

	// Fast path: cache entry still fresh per Cache-Control.
	if f.cache != nil {
		if cached, ok := f.cache.get(cacheKey); ok && time.Now().Before(cached.expires) {
			return &Index{Release: cached.release, ByArch: cached.archPkgs}, nil
		}
		// Shared-cache fast path: another replica may have already refreshed
		// Valkey more recently than our local copy (or we have no local copy
		// at all). Adopt it and skip the network entirely.
		if f.cache.valkey != nil {
			archs := append(append([]string{}, f.src.Archs...), "all")
			if cached, ok := f.cache.adoptFromValkey(ctx, cacheKey, f.src.Name, f.src.Suite, f.src.Component, archs); ok {
				slog.Debug("upstream index adopted from valkey (FetchIndex fast path)", "upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component)
				return &Index{Release: cached.release, ByArch: cached.archPkgs}, nil
			}
		}
	}

	// Resolve the conditional-GET/PDiff comparison basis once, here, and reuse
	// it at every point below that needs it (lock-contention fallback,
	// fetchVerifiedRelease's etag/lastMod, the 304 branch, and the
	// SHA256-reuse/PDiff logic) -- rather than re-resolving it independently
	// at each one, which previously cost a repeat Valkey round trip per call
	// site whenever the local cache had nothing (e.g. right after this
	// upstream's entry was evicted -- see IndexCache.EvictUpstream -- every
	// one of those redundant round trips added up across a whole layout's
	// worth of upstreams and measurably slowed down the next live rebuild).
	archsSuperset := append(append([]string{}, f.src.Archs...), "all")
	cachedEntry, _ := f.cachedForComparison(ctx, cacheKey, archsSuperset)

	// Nothing fresh anywhere. When Valkey coordination is enabled, only one
	// replica should hit the network for this upstream at a time.
	if f.cache != nil && f.cache.valkey != nil {
		acquired, stopLock, err := f.cache.acquireFetchLock(ctx, f.src.Name, f.src.Suite, f.src.Component)
		if err != nil {
			slog.Warn("valkey fetch lock unavailable, fetching directly", "upstream", f.src.Name, "err", err)
		} else if !acquired {
			// Another replica is already fetching. Don't duplicate the
			// upstream request if we have anything to serve meanwhile -- the
			// next refresh cycle picks up the fresh result via pub/sub or the
			// last_fetched reconciliation poll. With nothing to serve, fall
			// through and fetch anyway: availability wins over strict
			// single-fetcher exclusivity on a cold-start race.
			if cachedEntry != nil {
				slog.Debug("upstream index: another replica is fetching, serving stale comparison basis", "upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component)
				return &Index{Release: cachedEntry.release, ByArch: cachedEntry.archPkgs}, nil
			}
		} else {
			defer stopLock()
		}
	}

	// Bound this attempt when we already have per-arch data to fall back to
	// (see fastFallbackTimeout) -- a cachedEntry with no archPkgs at all (e.g.
	// a first-ever adopt that only got meta) has nothing to fall back to for
	// Packages specifically, so the full retry budget is worth spending then.
	haveArchFallback := cachedEntry != nil && len(cachedEntry.archPkgs) > 0
	fetchCtx, cancel := withFallbackTimeout(ctx, haveArchFallback)
	defer cancel()

	slog.Debug("upstream index: performing real network fetch", "upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component, "have_arch_fallback", haveArchFallback)
	releaseBody, resp, err := f.fetchVerifiedRelease(fetchCtx, cachedEntry)
	if err != nil {
		// All retries exhausted  --  serve stale cached data rather than failing hard.
		if cachedEntry != nil {
			return &Index{Release: cachedEntry.release, ByArch: cachedEntry.archPkgs}, nil
		}
		return nil, err
	}

	// 304: upstream says nothing changed  --  return cached index and extend expiry.
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		if cachedEntry != nil {
			updated := *cachedEntry
			updated.expires = parseExpiry(resp)
			if f.cache != nil {
				f.cache.store(cacheKey, &updated)
			}
			return &Index{Release: cachedEntry.release, ByArch: cachedEntry.archPkgs}, nil
		}
		// Cache miss despite 304 (shouldn't happen)  --  fall through to full fetch.
		releaseBody, _, err = f.fetchVerifiedReleaseFull(ctx)
		if err != nil {
			return nil, err
		}
		resp = nil
	}

	rel, err := apt.ParseRelease(bytes.NewReader(releaseBody))
	if err != nil {
		return nil, fmt.Errorf("parse Release: %w", err)
	}

	// Restrict to architectures that the upstream actually lists in the Release.
	archs := releaseServedArchs(rel, f.src.Component, f.src.Archs)
	if len(archs) < len(f.src.Archs) {
		slog.Debug("upstream does not serve all configured arches for component",
			"upstream", f.src.Name, "component", f.src.Component,
			"configured", f.src.Archs, "available", archs)
	}

	archPkgs := make(map[string][]apt.RawPkg, len(archs))
	var hasStaleMismatch bool
	for _, arch := range archs {
		// fetchCtx: bounded when a stale fallback exists for this upstream at
		// all (see above) so a hung Packages download degrades fast into the
		// per-arch stale fallback right below, same reasoning as
		// fetchVerifiedRelease's own use of it.
		paras, err := f.fetchPackagesMaybeReuse(fetchCtx, rel, arch, cachedEntry)
		if err != nil {
			if cachedEntry != nil {
				if stale, ok := cachedEntry.archPkgs[arch]; ok {
					if errors.Is(err, ErrDigestMismatch) {
						slog.Warn("transient digest mismatch (CDN/mirror inconsistency), serving stale packages",
							"upstream", f.src.Name, "suite", f.src.Suite, "arch", arch, "err", err)
						// Force cache expiry so the next fetch re-validates upstream
						// instead of returning this stale entry as "still fresh".
						if f.cache != nil {
							f.cache.expire(cacheKey)
						}
						hasStaleMismatch = true
					} else {
						slog.Warn("fetch failed, serving stale packages",
							"upstream", f.src.Name, "suite", f.src.Suite, "arch", arch, "err", err)
					}
					archPkgs[arch] = stale
					continue
				}
			}
			if errors.Is(err, ErrDigestMismatch) {
				slog.Error("transient digest mismatch (CDN/mirror inconsistency), no stale data available",
					"upstream", f.src.Name, "suite", f.src.Suite, "arch", arch, "err", err)
			} else {
				slog.Error("fetch failed, no stale data available",
					"upstream", f.src.Name, "suite", f.src.Suite, "arch", arch, "err", err)
			}
			continue
		}
		archPkgs[arch] = paras
	}

	if f.cache != nil {
		entry := &indexCacheEntry{
			release:  rel,
			archPkgs: archPkgs,
		}
		if resp != nil {
			entry.etag = resp.Header.Get("ETag")
			entry.lastMod = resp.Header.Get("Last-Modified")
			entry.expires = parseExpiry(resp)
		} else {
			entry.expires = time.Now().Add(5 * time.Minute)
		}
		f.cache.store(cacheKey, entry)
		if f.cache.valkey != nil {
			f.cache.publishToValkey(ctx, f.src.Name, f.src.Suite, f.src.Component, entry)
		}
	}

	return &Index{Release: rel, ByArch: archPkgs, HasStaleMismatch: hasStaleMismatch}, nil
}

// AdoptFromValkeyOutright serves this upstream's index straight from the
// local cache or Valkey's last-published copy, ignoring Expires entirely --
// unlike FetchIndex, which only serves outright when the data is still
// fresh per the upstream's own (often absent, defaulting to a bare 5
// minutes) Cache-Control. Intended for a caller that already knows, by some
// other means, that Valkey can be trusted right now regardless of that
// per-upstream freshness window -- see IndexCache.LayoutDataFresh: some
// replica refreshed this upstream's layout within the last
// schedule.refresh interval, which is the real staleness bound this system
// cares about, not the upstream mirror's own HTTP cache hint. Returns
// ok=false if neither local nor Valkey has anything at all; the caller
// should fall back to FetchIndex in that case.
func (f *Fetcher) AdoptFromValkeyOutright(ctx context.Context) (*Index, bool) {
	cacheKey := f.cacheKey()
	archs := append(append([]string{}, f.src.Archs...), "all")
	cached, ok := f.cachedForComparison(ctx, cacheKey, archs)
	if !ok || cached.release == nil {
		return nil, false
	}
	// An empty archPkgs is only a real miss when the cached Release itself
	// claims to serve at least one configured architecture but that data
	// just hasn't been cached (yet). When the Release confirms this
	// upstream serves none of them at all (see releaseServedArchs), an
	// empty archPkgs is already the correct, confirmed answer -- not a sign
	// this hasn't been checked, so there's nothing to gain by re-fetching
	// over the network to re-derive the same "nothing here" conclusion.
	if len(cached.archPkgs) == 0 && len(releaseServedArchs(cached.release, f.src.Component, f.src.Archs)) > 0 {
		return nil, false
	}
	if f.cache != nil {
		f.cache.store(cacheKey, cached)
	}
	return &Index{Release: cached.release, ByArch: cached.archPkgs}, true
}

// AdoptSourcesFromValkeyOutright is AdoptFromValkeyOutright's Sources
// counterpart -- see its doc comment for the full reasoning.
func (f *Fetcher) AdoptSourcesFromValkeyOutright(ctx context.Context) ([]apt.RawSrc, bool) {
	cacheKey := f.cacheKey()
	cached, ok := f.srcsCachedForComparison(ctx, cacheKey)
	if !ok || cached.srcsRelease == nil {
		return nil, false
	}
	// A nil srcs is only a real miss when the cached Release itself lists a
	// Sources index for this component but that data just hasn't been
	// cached (yet). When the Release confirms there's no Sources index at
	// all (see releaseListsSources), nil is already the correct, confirmed
	// answer -- not a sign nobody's checked, so there's nothing to gain by
	// re-fetching over the network to re-derive the same "nothing here"
	// conclusion.
	if cached.srcs == nil && releaseListsSources(cached.srcsRelease, f.src.Component) {
		return nil, false
	}
	if f.cache != nil {
		f.cache.updateSrcs(cacheKey, cached.srcsRelease, cached.srcs)
	}
	return cached.srcs, true
}

// cachedForComparison returns the best available entry to use as a
// conditional-GET (ETag/If-None-Match) and PDiff comparison basis for this
// fetcher's upstream+suite+component: the local cache if present, otherwise
// -- when Valkey backs the cache -- Valkey's last-published copy regardless
// of freshness (see IndexCache.adoptFromValkeyForComparison). This is what
// lets refreshLayoutGroup evict the local entry once it's done with a cycle
// (see IndexCache.EvictUpstream) without losing conditional-GET/PDiff
// efficiency on the next cycle: the comparison basis comes from Valkey
// instead, at the cost of one extra read when the local cache has nothing.
// Returns ok=false if neither has anything.
func (f *Fetcher) cachedForComparison(ctx context.Context, cacheKey string, archs []string) (*indexCacheEntry, bool) {
	if f.cache == nil {
		return nil, false
	}
	// cached.release == nil means this entry was stored by the Sources side
	// only (see IndexCache.store's merge -- a fresh entry created by
	// AdoptSourcesFromValkeyOutright/FetchSources carries no Index fields at
	// all). Treating that as an Index hit would wrongly skip the Valkey
	// check below and report no comparison basis even though Valkey has one.
	if cached, ok := f.cache.get(cacheKey); ok && cached.release != nil {
		return cached, true
	}
	if f.cache.valkey == nil {
		return nil, false
	}
	return f.cache.adoptFromValkeyForComparison(ctx, f.src.Name, f.src.Suite, f.src.Component, archs)
}

// fetchVerifiedRelease sends a conditional GET (ETag/Last-Modified) for
// InRelease and returns (verifiedBody, *http.Response, error). The response is
// nil when there was no network request (e.g. served from in-flight cache).
// The caller must check response.StatusCode for 304. cached is the caller's
// already-resolved comparison basis (see cachedForComparison) -- reused here
// rather than re-resolved, so a cache miss costs at most one Valkey round
// trip for the whole call, not one per place that needs it.
func (f *Fetcher) fetchVerifiedRelease(ctx context.Context, cached *indexCacheEntry) ([]byte, *http.Response, error) {
	url := f.distsURL("InRelease")
	var etag, lastMod string
	if cached != nil {
		etag = cached.etag
		lastMod = cached.lastMod
	}

	raw, resp, err := f.getConditional(ctx, url, etag, lastMod)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil, resp, nil
	}
	if resp.StatusCode == http.StatusOK {
		body, signerIDs, verr := signing.VerifyClearsigned(raw, f.src.VerifyKeys)
		if verr != nil {
			fps := make([]string, 0, len(f.src.VerifyKeys))
			for _, e := range f.src.VerifyKeys {
				fps = append(fps, hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))
			}
			slog.Error("InRelease signature verification failed, falling back to Release.gpg",
				"upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component,
				"err", verr, "trusted_key_fingerprints", fps, "actual_signer_key_ids", signerIDs)
			return f.fetchDetachedRelease(ctx)
		}
		return body, resp, nil
	}

	if resp.StatusCode != http.StatusNotFound {
		return nil, nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	// InRelease not found  --  fall back to detached.
	return f.fetchDetachedRelease(ctx)
}

// fetchVerifiedReleaseFull is a non-conditional full fetch, used when a 304
// arrived but we have no cached body (shouldn't happen in normal operation).
func (f *Fetcher) fetchVerifiedReleaseFull(ctx context.Context) ([]byte, *http.Response, error) {
	raw, resp, err := f.getConditional(ctx, f.distsURL("InRelease"), "", "")
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusOK {
		body, signerIDs, verr := signing.VerifyClearsigned(raw, f.src.VerifyKeys)
		if verr != nil {
			fps := make([]string, 0, len(f.src.VerifyKeys))
			for _, e := range f.src.VerifyKeys {
				fps = append(fps, hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))
			}
			slog.Error("InRelease signature verification failed, falling back to Release.gpg",
				"upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component,
				"err", verr, "trusted_key_fingerprints", fps, "actual_signer_key_ids", signerIDs)
			return f.fetchDetachedRelease(ctx)
		}
		return body, resp, nil
	}
	return f.fetchDetachedRelease(ctx)
}

func (f *Fetcher) fetchDetachedRelease(ctx context.Context) ([]byte, *http.Response, error) {
	releaseURL := f.distsURL("Release")
	release, resp, err := f.getConditional(ctx, releaseURL, "", "")
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch %s: status %d", releaseURL, resp.StatusCode)
	}
	gpgURL := f.distsURL("Release.gpg")
	sig, sigResp, err := f.getConditional(ctx, gpgURL, "", "")
	if err != nil {
		return nil, nil, err
	}
	if sigResp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch %s: status %d", gpgURL, sigResp.StatusCode)
	}
	signerIDs, err := signing.VerifyDetached(release, sig, f.src.VerifyKeys)
	if err != nil {
		fps := make([]string, 0, len(f.src.VerifyKeys))
		for _, e := range f.src.VerifyKeys {
			fps = append(fps, hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))
		}
		slog.Error("Release.gpg signature verification failed",
			"upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component,
			"err", err, "trusted_key_fingerprints", fps, "actual_signer_key_ids", signerIDs)
		return nil, nil, err
	}
	return release, resp, nil
}

// pkgVariant describes one compressed (or plain) Packages file variant.
type pkgVariant struct {
	ext    string
	decomp func([]byte) (io.Reader, error)
}

var pkgVariants = []pkgVariant{
	{"Packages.zst", func(d []byte) (io.Reader, error) {
		return zstd.NewReader(bytes.NewReader(d))
	}},
	{"Packages.gz", func(d []byte) (io.Reader, error) {
		return gzip.NewReader(bytes.NewReader(d))
	}},
	{"Packages.xz", func(d []byte) (io.Reader, error) {
		return xz.NewReader(bytes.NewReader(d))
	}},
	{"Packages.bz2", func(d []byte) (io.Reader, error) {
		return bzip2.NewReader(bytes.NewReader(d)), nil
	}},
	{"Packages", func(d []byte) (io.Reader, error) {
		return bytes.NewReader(d), nil
	}},
}

// fetchPackagesMaybeReuse fetches Packages for arch, reusing the cached
// paragraphs when the SHA256 in rel matches what was cached previously.
func (f *Fetcher) fetchPackagesMaybeReuse(ctx context.Context, rel *apt.Release, arch string, cached *indexCacheEntry) ([]apt.RawPkg, error) {
	base := fmt.Sprintf("%s/binary-%s/", f.src.Component, arch)
	byHash := acquireByHash(rel)
	if byHash {
		slog.Debug("upstream supports by-hash index fetching", "upstream", f.src.Name, "arch", arch)
	}

	// Check if the Release hash matches the cached version  --  if so, skip the fetch.
	if cached != nil && cached.release != nil {
		for _, v := range pkgVariants {
			relPath := base + v.ext
			newEntry, inNew := rel.Files[relPath]
			oldEntry, inOld := cached.release.Files[relPath]
			if inNew && inOld && newEntry.SHA256 == oldEntry.SHA256 {
				if paras, ok := cached.archPkgs[arch]; ok {
					return paras, nil
				}
			}
		}
	}

	// SHA256 changed  -- try PDiff before falling back to a full download.
	if cached != nil && cached.release != nil {
		if cachedSHA256 := cached.release.Files[base+"Packages"].SHA256; cachedSHA256 != "" {
			if updated, ok := f.tryPDiff(ctx, rel, base, arch, cachedSHA256, cached.archPkgs[arch]); ok {
				return updated, nil
			}
		}
	}

	for _, v := range pkgVariants {
		relPath := base + v.ext
		entry, ok := rel.Files[relPath]
		if !ok {
			continue
		}
		data, resp, err := f.getConditional(ctx, f.indexURL(relPath, entry.SHA256, byHash), "", "")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound && byHash {
			// by-hash not served for this variant; fall back to conventional path.
			data, resp, err = f.getConditional(ctx, f.distsURL(relPath), "", "")
			if err != nil {
				return nil, err
			}
		}
		if resp.StatusCode == http.StatusNotFound {
			slog.Warn("Packages variant not found, trying next", "url", f.distsURL(relPath), "arch", arch)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			slog.Warn("Packages variant bad status, trying next", "url", f.distsURL(relPath), "status", resp.StatusCode, "arch", arch)
			continue
		}
		if err := verifyDigest(data, entry.SHA256); err != nil {
			slog.Warn("Packages variant hash mismatch, trying next", "url", f.distsURL(relPath), "err", err, "arch", arch)
			continue
		}
		r, err := v.decomp(data)
		if err != nil {
			slog.Warn("Packages variant decompress failed, trying next", "url", f.distsURL(relPath), "err", err, "arch", arch)
			continue
		}
		if rc, ok := r.(io.Closer); ok {
			defer rc.Close()
		}
		return apt.ParsePackageRaws(r)
	}

	return nil, nil
}

// tryPDiff attempts to update cachedPkgs using PDiff patches from upstream.
// Returns (updatedPkgs, true) on success, (nil, false) if PDiff is unavailable
// or the patch chain cannot be applied (caller should fall back to full fetch).
func (f *Fetcher) tryPDiff(ctx context.Context, rel *apt.Release, base, arch, cachedSHA256 string, cachedPkgs []apt.RawPkg) ([]apt.RawPkg, bool) {
	diffRelPath := base + "Packages.diff/Index"
	relEntry, ok := rel.Files[diffRelPath]
	if !ok {
		return nil, false
	}

	data, resp, err := f.getConditional(ctx, f.distsURL(diffRelPath), "", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, false
	}
	if err := verifyDigest(data, relEntry.SHA256); err != nil {
		slog.Warn("pdiff: index digest mismatch", "upstream", f.src.Name, "arch", arch, "err", err)
		return nil, false
	}

	idx, err := apt.ParsePDiffIndex(bytes.NewReader(data))
	if err != nil {
		slog.Warn("pdiff: parse index failed", "upstream", f.src.Name, "arch", arch, "err", err)
		return nil, false
	}

	chain := idx.PatchChain(cachedSHA256)
	if chain == nil {
		return nil, false // cached version not in history; need full fetch
	}
	if len(chain) == 0 {
		return cachedPkgs, true // already current
	}

	pkgs := make([]apt.RawPkg, len(cachedPkgs))
	copy(pkgs, cachedPkgs)

	for _, name := range chain {
		patchRelPath := base + "Packages.diff/" + name + ".gz"
		pdata, presp, perr := f.getConditional(ctx, f.distsURL(patchRelPath), "", "")
		if perr != nil || presp.StatusCode != http.StatusOK {
			slog.Warn("pdiff: fetch patch failed", "upstream", f.src.Name, "name", name)
			return nil, false
		}
		entry, ok := rel.Files[patchRelPath]
		if !ok {
			slog.Warn("pdiff: patch not listed in Release", "upstream", f.src.Name, "name", name)
			return nil, false
		}
		if err := verifyDigest(pdata, entry.SHA256); err != nil {
			slog.Warn("pdiff: patch digest mismatch", "name", name, "err", err)
			return nil, false
		}
		gr, gerr := gzip.NewReader(bytes.NewReader(pdata))
		if gerr != nil {
			return nil, false
		}
		decompressed, derr := io.ReadAll(gr)
		gr.Close()
		if derr != nil {
			return nil, false
		}
		pkgs, err = apt.ApplyEdPatch(pkgs, decompressed)
		if err != nil {
			slog.Warn("pdiff: apply failed", "upstream", f.src.Name, "name", name, "err", err)
			return nil, false
		}
	}

	// Verify the final result matches the expected SHA256 from the PDiff Index.
	// This catches bugs in patch application, wrong patch sequences, or any
	// other corruption that slipped past per-patch verification.
	if err := verifyDigest(apt.SerializeRawPkgs(pkgs), idx.CurrentSHA256); err != nil {
		slog.Warn("pdiff: final Packages SHA256 mismatch after applying patches  -- falling back to full fetch",
			"upstream", f.src.Name, "arch", arch, "err", err)
		return nil, false
	}

	slog.Debug("pdiff: updated Packages index incrementally", "upstream", f.src.Name, "arch", arch, "patches", len(chain))
	return pkgs, true
}

var srcVariants = []pkgVariant{
	{"Sources.zst", func(d []byte) (io.Reader, error) {
		return zstd.NewReader(bytes.NewReader(d))
	}},
	{"Sources.gz", func(d []byte) (io.Reader, error) {
		return gzip.NewReader(bytes.NewReader(d))
	}},
	{"Sources.xz", func(d []byte) (io.Reader, error) {
		return xz.NewReader(bytes.NewReader(d))
	}},
	{"Sources.bz2", func(d []byte) (io.Reader, error) {
		return bzip2.NewReader(bytes.NewReader(d)), nil
	}},
	{"Sources", func(d []byte) (io.Reader, error) {
		return bytes.NewReader(d), nil
	}},
}

// tryPDiffSrc attempts to update cachedSrcs using PDiff patches from upstream.
// Returns (updatedSrcs, true) on success, (nil, false) if PDiff is unavailable
// or the patch chain cannot be applied (caller should fall back to full fetch).
func (f *Fetcher) tryPDiffSrc(ctx context.Context, rel *apt.Release, base, cachedSHA256 string, cachedSrcs []apt.RawSrc) ([]apt.RawSrc, bool) {
	diffRelPath := base + "Sources.diff/Index"
	relEntry, ok := rel.Files[diffRelPath]
	if !ok {
		return nil, false
	}

	data, resp, err := f.getConditional(ctx, f.distsURL(diffRelPath), "", "")
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, false
	}
	if err := verifyDigest(data, relEntry.SHA256); err != nil {
		slog.Warn("pdiff: sources index digest mismatch", "upstream", f.src.Name, "component", f.src.Component, "err", err)
		return nil, false
	}

	idx, err := apt.ParsePDiffIndex(bytes.NewReader(data))
	if err != nil {
		slog.Warn("pdiff: parse sources index failed", "upstream", f.src.Name, "component", f.src.Component, "err", err)
		return nil, false
	}

	chain := idx.PatchChain(cachedSHA256)
	if chain == nil {
		return nil, false // cached version not in history; need full fetch
	}
	if len(chain) == 0 {
		return cachedSrcs, true // already current
	}

	srcs := make([]apt.RawSrc, len(cachedSrcs))
	copy(srcs, cachedSrcs)

	for _, name := range chain {
		patchRelPath := base + "Sources.diff/" + name + ".gz"
		pdata, presp, perr := f.getConditional(ctx, f.distsURL(patchRelPath), "", "")
		if perr != nil || presp.StatusCode != http.StatusOK {
			slog.Warn("pdiff: fetch sources patch failed", "upstream", f.src.Name, "component", f.src.Component, "name", name)
			return nil, false
		}
		entry, ok := rel.Files[patchRelPath]
		if !ok {
			slog.Warn("pdiff: sources patch not listed in Release", "upstream", f.src.Name, "component", f.src.Component, "name", name)
			return nil, false
		}
		if err := verifyDigest(pdata, entry.SHA256); err != nil {
			slog.Warn("pdiff: sources patch digest mismatch", "upstream", f.src.Name, "component", f.src.Component, "name", name, "err", err)
			return nil, false
		}
		gr, gerr := gzip.NewReader(bytes.NewReader(pdata))
		if gerr != nil {
			return nil, false
		}
		decompressed, derr := io.ReadAll(gr)
		gr.Close()
		if derr != nil {
			return nil, false
		}
		srcs, err = apt.ApplyEdPatchSrc(srcs, decompressed)
		if err != nil {
			slog.Warn("pdiff: apply sources patch failed", "upstream", f.src.Name, "component", f.src.Component, "name", name, "err", err)
			return nil, false
		}
	}

	// Verify final result matches expected SHA256 from the PDiff Index.
	if err := verifyDigest(apt.SerializeRawSrcs(srcs), idx.CurrentSHA256); err != nil {
		slog.Warn("pdiff: final Sources SHA256 mismatch after applying patches  -- falling back to full fetch",
			"upstream", f.src.Name, "component", f.src.Component, "err", err)
		return nil, false
	}

	slog.Debug("pdiff: updated Sources index incrementally", "upstream", f.src.Name, "component", f.src.Component, "patches", len(chain))
	return srcs, true
}

// srcsCachedForComparison is FetchSources' counterpart to
// cachedForComparison: the local cache if present, otherwise (when Valkey
// backs the cache) Valkey's last-published release+srcs regardless of
// freshness. See cachedForComparison's doc comment for why this exists.
func (f *Fetcher) srcsCachedForComparison(ctx context.Context, cacheKey string) (*indexCacheEntry, bool) {
	if f.cache == nil {
		return nil, false
	}
	// cached.srcsRelease == nil means this entry was stored by the Index
	// side only (see IndexCache.store's merge -- a fresh entry created by
	// AdoptFromValkeyOutright/FetchIndex carries no Sources fields at all,
	// since avail.Build always fetches every upstream's Index before it
	// starts any Sources fetch, so the Index side's store() always runs
	// first on a cold process). Treating that as a Sources hit would wrongly
	// skip the Valkey check below and report no comparison basis every
	// single time, even though Valkey has one. srcsRelease (not srcs) is
	// the right signal: it's set whenever the Sources side has actually
	// resolved this upstream, including a confirmed-empty result (a
	// component with no Sources index at all -- see releaseListsSources),
	// which leaves srcs nil but is still a fully resolved answer worth
	// trusting locally rather than re-checking Valkey every time.
	if cached, ok := f.cache.get(cacheKey); ok && cached.srcsRelease != nil {
		return cached, true
	}
	if f.cache.valkey == nil {
		return nil, false
	}
	return f.cache.adoptSrcsFromValkeyForComparison(ctx, f.src.Name, f.src.Suite, f.src.Component)
}

// FetchSources downloads and parses the upstream Sources index for the configured
// component. Returns nil, nil when no Sources index is listed in the Release.
func (f *Fetcher) FetchSources(ctx context.Context) ([]apt.RawSrc, error) {
	cacheKey := f.cacheKey()

	// Shared-cache fast path: another replica may have already refreshed
	// Valkey's Sources data more recently than our local copy. Adopt it and
	// skip the network entirely, mirroring FetchIndex's fast path.
	if f.cache != nil && f.cache.valkey != nil {
		if srcs, ok := f.cache.adoptSrcsFromValkey(ctx, cacheKey, f.src.Name, f.src.Suite, f.src.Component); ok {
			slog.Debug("upstream Sources adopted from valkey (FetchSources fast path)", "upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component)
			return srcs, nil
		}
	}

	// Resolve the comparison basis once and reuse it below (lock-contention
	// fallback, fetchVerifiedRelease's etag/lastMod, and the SHA256-reuse/
	// PDiff logic) -- see FetchIndex's own cachedEntry resolution for why
	// this must happen exactly once, not once per call site.
	cachedEntry, _ := f.srcsCachedForComparison(ctx, cacheKey)

	// Nothing fresh anywhere. When Valkey coordination is enabled, only one
	// replica should hit the network for this upstream at a time.
	if f.cache != nil && f.cache.valkey != nil {
		acquired, stopLock, err := f.cache.acquireFetchLock(ctx, f.src.Name, f.src.Suite, f.src.Component)
		if err != nil {
			slog.Warn("valkey fetch lock unavailable, fetching directly", "upstream", f.src.Name, "err", err)
		} else if !acquired {
			// Another replica is already fetching -- serve local stale srcs
			// if we have any rather than duplicate the request.
			if cachedEntry != nil && cachedEntry.srcs != nil {
				slog.Debug("upstream Sources: another replica is fetching, serving stale comparison basis", "upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component)
				return cachedEntry.srcs, nil
			}
		} else {
			defer stopLock()
		}
	}

	// Bound this attempt (InRelease plus, below, the Sources file itself) when
	// we already have srcs to fall back to -- see fastFallbackTimeout.
	haveSrcsFallback := cachedEntry != nil && cachedEntry.srcs != nil
	fetchCtx, cancel := withFallbackTimeout(ctx, haveSrcsFallback)
	defer cancel()

	slog.Debug("upstream Sources: performing real network fetch", "upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component, "have_srcs_fallback", haveSrcsFallback)
	releaseBody, resp, err := f.fetchVerifiedRelease(fetchCtx, cachedEntry)
	if err != nil {
		// All retries exhausted  --  serve stale cached data rather than failing
		// hard, mirroring FetchIndex's own fallback. Without this, a slow/down
		// upstream mirror would discard a perfectly usable (if slightly stale)
		// Valkey- or locally-cached copy just because the InRelease
		// conditional-GET itself timed out, even though nothing about that
		// copy's own content is actually in question.
		if haveSrcsFallback {
			return cachedEntry.srcs, nil
		}
		return nil, err
	}

	var rel *apt.Release
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		// InRelease unchanged  -- return cached srcs if available.
		if cachedEntry != nil && cachedEntry.srcs != nil {
			return cachedEntry.srcs, nil
		}
		if cachedEntry != nil {
			rel = cachedEntry.release
		}
	}
	if rel == nil && releaseBody != nil {
		rel, err = apt.ParseRelease(bytes.NewReader(releaseBody))
		if err != nil {
			return nil, fmt.Errorf("parse Release for sources: %w", err)
		}
	}
	if rel == nil {
		return nil, nil
	}
	base := f.src.Component + "/source/"

	// Cache hit: if SHA256 unchanged, return cached srcs immediately.
	if cachedEntry != nil && cachedEntry.srcsRelease != nil && cachedEntry.srcs != nil {
		for _, v := range srcVariants {
			relPath := base + v.ext
			newEntry, inNew := rel.Files[relPath]
			oldEntry, inOld := cachedEntry.srcsRelease.Files[relPath]
			if inNew && inOld && newEntry.SHA256 == oldEntry.SHA256 {
				return cachedEntry.srcs, nil
			}
		}

		// SHA256 changed  -- try PDiff.
		if cachedSHA256 := cachedEntry.srcsRelease.Files[base+"Sources"].SHA256; cachedSHA256 != "" {
			if updated, ok := f.tryPDiffSrc(ctx, rel, base, cachedSHA256, cachedEntry.srcs); ok {
				if f.cache != nil {
					f.cache.updateSrcs(cacheKey, rel, updated)
					if f.cache.valkey != nil {
						f.cache.publishSrcsToValkey(ctx, f.src.Name, f.src.Suite, f.src.Component, updated)
					}
				}
				return updated, nil
			}
		}
	}

	srcs, err := f.fetchSourcesFile(fetchCtx, rel, base)
	if err != nil {
		// Network/transport failure downloading the Sources file itself (as
		// opposed to a missing/bad-status variant, which fetchSourcesFile
		// already handles by trying the next one) -- serve stale cached data
		// rather than failing hard, mirroring FetchIndex's per-arch stale
		// fallback in its own caller of fetchPackagesMaybeReuse. Without this,
		// a slow/down upstream mirror would drop Sources for this upstream
		// entirely from a live rebuild, even with a perfectly usable (if
		// slightly stale) copy already in hand from cachedForComparison above.
		if haveSrcsFallback {
			slog.Warn("fetch failed, serving stale sources",
				"upstream", f.src.Name, "suite", f.src.Suite, "component", f.src.Component, "err", err)
			return cachedEntry.srcs, nil
		}
		return nil, err
	}
	if srcs != nil && f.cache != nil {
		f.cache.updateSrcs(cacheKey, rel, srcs)
		if f.cache.valkey != nil {
			f.cache.publishSrcsToValkey(ctx, f.src.Name, f.src.Suite, f.src.Component, srcs)
		}
	}
	return srcs, nil
}

// fetchSourcesFile downloads and parses the Sources file for one component,
// trying compressed variants in the same order as srcVariants before giving
// up. Returns (nil, nil) if the Release lists no variant fetchSourcesFile
// could retrieve.
func (f *Fetcher) fetchSourcesFile(ctx context.Context, rel *apt.Release, base string) ([]apt.RawSrc, error) {
	byHash := acquireByHash(rel)
	for _, v := range srcVariants {
		relPath := base + v.ext
		entry, ok := rel.Files[relPath]
		if !ok {
			continue
		}
		data, resp, err := f.getConditional(ctx, f.indexURL(relPath, entry.SHA256, byHash), "", "")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound && byHash {
			data, resp, err = f.getConditional(ctx, f.distsURL(relPath), "", "")
			if err != nil {
				return nil, err
			}
		}
		if resp.StatusCode == http.StatusNotFound {
			slog.Warn("Sources variant not found, trying next", "url", f.distsURL(relPath))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			slog.Warn("Sources variant bad status, trying next", "url", f.distsURL(relPath), "status", resp.StatusCode)
			continue
		}
		if err := verifyDigest(data, entry.SHA256); err != nil {
			slog.Warn("Sources variant hash mismatch, trying next", "url", f.distsURL(relPath), "err", err)
			continue
		}
		r, err := v.decomp(data)
		if err != nil {
			slog.Warn("Sources variant decompress failed, trying next", "url", f.distsURL(relPath), "err", err)
			continue
		}
		if rc, ok := r.(io.Closer); ok {
			defer rc.Close()
		}
		return apt.ParseSourceRaws(r)
	}
	return nil, nil
}

// DownloadSourceFile fetches a single source package file from the upstream.
// directory is the upstream's Directory: field (e.g. "pool/main/a/apt");
// filename is the bare filename (e.g. "apt_2.6.1.dsc").
func (f *Fetcher) DownloadSourceFile(ctx context.Context, directory, filename, expectedSHA256 string) ([]byte, error) {
	url := f.base() + "/" + strings.TrimLeft(directory, "/") + "/" + filename
	data, resp, err := f.getConditional(ctx, url, "", "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download source %s: status %d", filename, resp.StatusCode)
	}
	if err := verifyDigest(data, expectedSHA256); err != nil {
		return nil, fmt.Errorf("source %s: %w", filename, err)
	}
	return data, nil
}

// DownloadDeb fetches a package by its upstream-relative Filename and verifies
// its content against the expected SHA256 before returning the bytes.
func (f *Fetcher) DownloadDeb(ctx context.Context, filename, expectedSHA256 string) ([]byte, error) {
	url := f.base() + "/" + strings.TrimLeft(filename, "/")
	data, resp, err := f.getConditional(ctx, url, "", "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", filename, resp.StatusCode)
	}
	if err := verifyDigest(data, expectedSHA256); err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	return data, nil
}

// getConditional issues a GET with optional ETag/Last-Modified validators.
// On 304 the body is empty. The response is always non-nil on nil error.
func (f *Fetcher) getConditional(ctx context.Context, url, etag, lastMod string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if f.src.Username != "" {
		req.SetBasicAuth(f.src.Username, f.src.Password)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, resp, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, resp, nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, err
	}
	return data, resp, nil
}

// ErrDigestMismatch is returned when a fetched file's SHA256 does not match
// the value declared in the Release file. It typically indicates the mirror is
// mid-sync and the Packages file has not yet been pushed after InRelease.
var ErrDigestMismatch = errors.New("sha256 mismatch")

func verifyDigest(data []byte, expected string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("%w: got %s want %s", ErrDigestMismatch, got, expected)
	}
	return nil
}

// Digest computes the hex SHA256 of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

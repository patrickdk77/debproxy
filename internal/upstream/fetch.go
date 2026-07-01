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

// FetchIndex downloads, signature-verifies, and parses the suite Release plus
// the Packages indices for the configured component and architectures.
// When a cache is configured it sends conditional requests (ETag/304) and
// reuses previously-parsed Packages data if the Release hash is unchanged.
func (f *Fetcher) FetchIndex(ctx context.Context) (*Index, error) {
	inReleaseURL := f.distsURL("InRelease")
	// The cache key includes the component because the same upstream URL+suite
	// may be used across multiple component layouts (e.g. ubuntu-main is listed
	// in main, universe, restricted, and multiverse). Without the component, the
	// first layout's Packages data would be returned for all others.
	cacheKey := inReleaseURL + "\x00" + f.src.Component

	// Fast path: cache entry still fresh per Cache-Control.
	if f.cache != nil {
		if cached, ok := f.cache.get(cacheKey); ok && time.Now().Before(cached.expires) {
			return &Index{Release: cached.release, ByArch: cached.archPkgs}, nil
		}
	}

	releaseBody, resp, err := f.fetchVerifiedRelease(ctx)
	if err != nil {
		// All retries exhausted  --  serve stale cached data rather than failing hard.
		if f.cache != nil {
			if cached, ok := f.cache.get(cacheKey); ok {
				return &Index{Release: cached.release, ByArch: cached.archPkgs}, nil
			}
		}
		return nil, err
	}

	// 304: upstream says nothing changed  --  return cached index and extend expiry.
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		if f.cache != nil {
			if cached, ok := f.cache.get(cacheKey); ok {
				updated := *cached
				updated.expires = parseExpiry(resp)
				f.cache.store(cacheKey, &updated)
				return &Index{Release: cached.release, ByArch: cached.archPkgs}, nil
			}
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

	// Fetch per-arch Packages, reusing cached data where the SHA256 is unchanged.
	var cachedEntry *indexCacheEntry
	if f.cache != nil {
		cachedEntry, _ = f.cache.get(cacheKey)
	}

	// Restrict to architectures that the upstream actually lists in the Release.
	// The Architectures field is not used because upstreams like archive.ubuntu.com
	// list all architectures there even though arm64 Packages are only served from
	// ports.ubuntu.com. Checking rel.Files is authoritative: if no Packages variant
	// is listed for a given arch, the upstream does not serve it.
	archs := make([]string, 0, len(f.src.Archs))
	for _, arch := range f.src.Archs {
		prefix := f.src.Component + "/binary-" + arch + "/Packages"
		for path := range rel.Files {
			if strings.HasPrefix(path, prefix) {
				archs = append(archs, arch)
				break
			}
		}
	}
	if len(archs) < len(f.src.Archs) {
		slog.Debug("upstream does not serve all configured arches for component",
			"upstream", f.src.Name, "component", f.src.Component,
			"configured", f.src.Archs, "available", archs)
	}

	archPkgs := make(map[string][]apt.RawPkg, len(archs))
	var hasStaleMismatch bool
	for _, arch := range archs {
		paras, err := f.fetchPackagesMaybeReuse(ctx, rel, arch, cachedEntry)
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
	}

	return &Index{Release: rel, ByArch: archPkgs, HasStaleMismatch: hasStaleMismatch}, nil
}

// fetchVerifiedRelease sends a conditional GET (ETag/Last-Modified) for
// InRelease and returns (verifiedBody, *http.Response, error). The response is
// nil when there was no network request (e.g. served from in-flight cache).
// The caller must check response.StatusCode for 304.
func (f *Fetcher) fetchVerifiedRelease(ctx context.Context) ([]byte, *http.Response, error) {
	url := f.distsURL("InRelease")
	cacheKey := url + "\x00" + f.src.Component
	var etag, lastMod string
	if f.cache != nil {
		if cached, ok := f.cache.get(cacheKey); ok {
			etag = cached.etag
			lastMod = cached.lastMod
		}
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

	// SHA256 changed — try PDiff before falling back to a full download.
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
	if _, ok := rel.Files[diffRelPath]; !ok {
		return nil, false
	}

	data, resp, err := f.getConditional(ctx, f.distsURL(diffRelPath), "", "")
	if err != nil || resp.StatusCode != http.StatusOK {
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
		slog.Warn("pdiff: final Packages SHA256 mismatch after applying patches — falling back to full fetch",
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
	if _, ok := rel.Files[diffRelPath]; !ok {
		return nil, false
	}

	data, resp, err := f.getConditional(ctx, f.distsURL(diffRelPath), "", "")
	if err != nil || resp.StatusCode != http.StatusOK {
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
		slog.Warn("pdiff: final Sources SHA256 mismatch after applying patches — falling back to full fetch",
			"upstream", f.src.Name, "component", f.src.Component, "err", err)
		return nil, false
	}

	slog.Debug("pdiff: updated Sources index incrementally", "upstream", f.src.Name, "component", f.src.Component, "patches", len(chain))
	return srcs, true
}

// FetchSources downloads and parses the upstream Sources index for the configured
// component. Returns nil, nil when no Sources index is listed in the Release.
func (f *Fetcher) FetchSources(ctx context.Context) ([]apt.RawSrc, error) {
	inReleaseURL := f.distsURL("InRelease")
	cacheKey := inReleaseURL + "\x00" + f.src.Component

	releaseBody, resp, err := f.fetchVerifiedRelease(ctx)
	if err != nil {
		return nil, err
	}

	var rel *apt.Release
	var cachedEntry *indexCacheEntry
	if f.cache != nil {
		cachedEntry, _ = f.cache.get(cacheKey)
	}
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		// InRelease unchanged — return cached srcs if available.
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

		// SHA256 changed — try PDiff.
		if cachedSHA256 := cachedEntry.srcsRelease.Files[base+"Sources"].SHA256; cachedSHA256 != "" {
			if updated, ok := f.tryPDiffSrc(ctx, rel, base, cachedSHA256, cachedEntry.srcs); ok {
				if f.cache != nil {
					f.cache.updateSrcs(cacheKey, rel, updated)
				}
				return updated, nil
			}
		}
	}

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
		srcs, err := apt.ParseSourceRaws(r)
		if err != nil {
			return nil, err
		}
		if srcs != nil && f.cache != nil {
			f.cache.updateSrcs(cacheKey, rel, srcs)
		}
		return srcs, nil
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

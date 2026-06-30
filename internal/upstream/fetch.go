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

	archPkgs := make(map[string][]apt.RawPkg, len(f.src.Archs))
	var hasStaleMismatch bool
	for _, arch := range f.src.Archs {
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
	{"Packages.gz", func(d []byte) (io.Reader, error) {
		return gzip.NewReader(bytes.NewReader(d))
	}},
	{"Packages.xz", func(d []byte) (io.Reader, error) {
		return xz.NewReader(bytes.NewReader(d))
	}},
	{"Packages.zst", func(d []byte) (io.Reader, error) {
		return zstd.NewReader(bytes.NewReader(d))
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

	for _, v := range pkgVariants {
		relPath := base + v.ext
		entry, ok := rel.Files[relPath]
		if !ok {
			continue
		}
		data, resp, err := f.getConditional(ctx, f.distsURL(relPath), "", "")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			// File listed in Release but not served here — try the next variant.
			slog.Warn("Packages file listed in Release but not found, trying next variant",
				"url", f.distsURL(relPath), "arch", arch)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: status %d", relPath, resp.StatusCode)
		}
		if err := verifyDigest(data, entry.SHA256); err != nil {
			return nil, fmt.Errorf("%s: %w", relPath, err)
		}
		r, err := v.decomp(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", relPath, err)
		}
		if rc, ok := r.(io.Closer); ok {
			defer rc.Close()
		}
		return apt.ParsePackageRaws(r)
	}

	return nil, nil
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

package upstream

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/debproxy/debproxy/internal/apt"
)

// IndexCache stores parsed and GPG-verified upstream index data keyed by
// InRelease URL. A cache hit allows conditional re-validation via ETag/304
// rather than re-fetching and re-verifying the full content.
type IndexCache struct {
	mu      sync.Mutex
	entries map[string]*indexCacheEntry
}

type indexCacheEntry struct {
	// HTTP re-validation handles
	etag    string
	lastMod string
	expires time.Time

	// Parsed content (already GPG-verified and SHA256-verified)
	release  *apt.Release
	archPkgs map[string][]apt.RawPkg // arch -> verified+parsed Packages stanzas

	// Sources index cache
	srcsRelease *apt.Release // InRelease from last successful Sources fetch
	srcs        []apt.RawSrc // parsed Sources stanzas from that fetch
}

// NewIndexCache creates an empty cache.
func NewIndexCache() *IndexCache {
	return &IndexCache{entries: map[string]*indexCacheEntry{}}
}

// get returns (entry, ok). The entry must not be mutated by callers.
func (c *IndexCache) get(inReleaseURL string) (*indexCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[inReleaseURL]
	return e, ok
}

// store saves a cache entry. Any srcsRelease/srcs already in the cache for this
// key are preserved so a FetchIndex call cannot clobber Sources data written by
// a concurrent or prior FetchSources call.
func (c *IndexCache) store(key string, e *indexCacheEntry) {
	c.mu.Lock()
	if old, ok := c.entries[key]; ok && (old.srcsRelease != nil || old.srcs != nil) {
		merged := *e
		merged.srcsRelease = old.srcsRelease
		merged.srcs = old.srcs
		c.entries[key] = &merged
	} else {
		c.entries[key] = e
	}
	c.mu.Unlock()
}

// expire marks a cache entry as immediately expired so the next FetchIndex call
// performs a real upstream request. The entry itself is kept so stale archPkgs
// remain available as a fallback if the next fetch also fails.
func (c *IndexCache) expire(key string) {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		expired := *e
		expired.expires = time.Time{}
		c.entries[key] = &expired
	}
	c.mu.Unlock()
}

// ExpireAll marks every entry as immediately expired so the next FetchIndex
// calls perform real upstream requests. Cached archPkgs are retained so they
// remain available for PDiff comparison and stale-fallback on the next fetch.
func (c *IndexCache) ExpireAll() {
	c.mu.Lock()
	for k, e := range c.entries {
		expired := *e
		expired.expires = time.Time{}
		c.entries[k] = &expired
	}
	c.mu.Unlock()
}

// updateSrcs stores srcsRelease and srcs into the cache entry for key.
// If no entry exists for key, a minimal entry is created.
func (c *IndexCache) updateSrcs(key string, rel *apt.Release, srcs []apt.RawSrc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		updated := *e
		updated.srcsRelease = rel
		updated.srcs = srcs
		c.entries[key] = &updated
	} else {
		c.entries[key] = &indexCacheEntry{
			srcsRelease: rel,
			srcs:        srcs,
		}
	}
}

// parseExpiry derives an absolute expiry time from a response's cache headers.
// Falls back to now+5min if none are present.
func parseExpiry(resp *http.Response) time.Time {
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		for _, tok := range strings.Split(cc, ",") {
			tok = strings.TrimSpace(tok)
			if strings.EqualFold(tok, "no-cache") || strings.EqualFold(tok, "no-store") {
				return time.Time{} // always revalidate
			}
			if after, ok := strings.CutPrefix(tok, "max-age="); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(after)); err == nil && n > 0 {
					base := time.Now()
					if d := resp.Header.Get("Date"); d != "" {
						if t, err := http.ParseTime(d); err == nil {
							ageS, _ := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Age")))
							base = t.Add(time.Duration(ageS) * time.Second)
						}
					}
					return base.Add(time.Duration(n) * time.Second)
				}
			}
		}
	}
	if exp := resp.Header.Get("Expires"); exp != "" {
		if t, err := http.ParseTime(exp); err == nil && t.After(time.Now()) {
			return t
		}
	}
	return time.Now().Add(5 * time.Minute)
}

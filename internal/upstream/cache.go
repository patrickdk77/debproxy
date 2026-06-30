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

// store saves a cache entry.
func (c *IndexCache) store(inReleaseURL string, e *indexCacheEntry) {
	c.mu.Lock()
	c.entries[inReleaseURL] = e
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

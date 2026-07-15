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
	// valkey optionally backs this cache with a shared Valkey deployment so
	// multiple debproxy replicas avoid redundant upstream fetches. Nil
	// unless EnableValkey is called; see valkey.go.
	valkey *valkeyBacking

	// buildMu serializes avail.Build (and the upstream fetches/Valkey fetch
	// locks it can trigger via FetchIndex/FetchSources) across every caller
	// sharing this cache. A single debproxy process builds through the same
	// IndexCache from more than one place -- the periodic background
	// refresher and on-demand /live request handling (cold-start build,
	// background rebuild-when-stale, digest-mismatch retry) -- and without
	// this, a live request's build could run fully concurrently with the
	// refresher's own build for a different layout, each independently
	// holding a Valkey fetch lock and resident merge memory at the same
	// time. This is intentionally distinct from mu above: mu protects this
	// cache's own entries map for concurrent reads/writes (a much
	// finer-grained, unrelated concern); buildMu is a coarser, whole-build
	// serialization point.
	buildMu sync.Mutex
}

// Lock and Unlock implement sync.Locker, serializing avail.Build across
// every caller sharing this cache. See buildMu.
func (c *IndexCache) Lock()   { c.buildMu.Lock() }
func (c *IndexCache) Unlock() { c.buildMu.Unlock() }

// TryLock acquires buildMu only if it's immediately free, returning false
// without blocking otherwise. Used by callers that must never wait on an
// unrelated build already in progress (see server.go's cold-start live
// build) but still want to close the common, uncontended case of the same
// cross-layout memory overlap buildMu exists to prevent.
func (c *IndexCache) TryLock() bool { return c.buildMu.TryLock() }

type indexCacheEntry struct {
	// HTTP re-validation handles
	etag    string
	lastMod string
	expires time.Time

	// Parsed content (already GPG-verified and SHA256-verified)
	release  *apt.Release
	archPkgs map[string][]apt.RawPkg // arch -> verified+parsed Packages stanzas

	// archsComplete is false when at least one requested arch's Packages
	// data is missing from archPkgs because reading it failed (a transient
	// Valkey error, most commonly -- see fetchArchPkgs), as opposed to that
	// arch genuinely having nothing to serve. archPkgs alone can't tell
	// these two cases apart: both leave the arch's key absent. Callers that
	// treat archPkgs as a complete, trustworthy picture (AdoptFromValkeyOutright,
	// FetchIndex's Valkey-adopt fast path, and the 304 shortcut) must check
	// this first; callers that only want a best-effort comparison/fallback
	// basis (PDiff, stale-on-error) don't need to.
	archsComplete bool

	// Sources index cache
	srcsRelease *apt.Release // InRelease from last successful Sources fetch
	srcs        []apt.RawSrc // parsed Sources stanzas from that fetch
}

// NewIndexCache creates an empty cache.
func NewIndexCache() *IndexCache {
	return &IndexCache{entries: map[string]*indexCacheEntry{}}
}

// WithoutLocalState returns a new IndexCache that shares c's Valkey backing
// (if any) but starts with no local entries. Every fast path in FetchIndex/
// AdoptFromValkeyOutright/cachedForComparison checks this cache's local
// entries map before ever consulting Valkey, so a caller sharing c directly
// would silently keep re-serving c's own possibly-stale-or-incomplete local
// copy (e.g. from a degraded build) forever, even though Valkey -- or the
// real upstream -- already has the correct answer. Handing out a fresh local
// map (while reusing the same underlying Valkey client/connection, so this
// is cheap) forces a real check. Used by avail.ResolvePoolPath's live-path
// fallback, which exists specifically to answer "does this actually exist
// right now" independent of whatever this process's own cache believes.
func (c *IndexCache) WithoutLocalState() *IndexCache {
	c.mu.Lock()
	v := c.valkey
	c.mu.Unlock()
	fresh := NewIndexCache()
	fresh.valkey = v
	return fresh
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

// EvictUpstream removes the cache entry for one upstream+suite+component
// (the same key FetchIndex/FetchSources use), if this cache is Valkey-backed
// -- a no-op otherwise, since without Valkey this cache is the only copy of
// the data, and evicting it would force a full re-fetch (GPG verify,
// decompress, parse) on the next use instead of a cheap Valkey read. Called
// once a refresh cycle is done using an upstream's data (see
// refreshLayoutGroup) so a long-lived process doesn't keep every layout's
// fetched Packages/Sources resident between refreshes -- Valkey remains the
// durable copy, and FetchIndex/FetchSources re-adopt a fresh or
// comparison-only copy from it on the next call (see adoptFromValkey and
// adoptFromValkeyForComparison in valkey.go).
func (c *IndexCache) EvictUpstream(inReleaseURL, component string) {
	if c.valkey == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, inReleaseURL+"\x00"+component)
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

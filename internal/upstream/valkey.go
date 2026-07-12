package upstream

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// valkeyBacking holds the optional shared-cache wiring for an IndexCache. A
// cluster of debproxy replicas that share the same Valkey deployment avoid
// redundant upstream fetches this way: whichever replica actually fetches
// writes its result here, and the others adopt it instead of independently
// re-fetching.
type valkeyBacking struct {
	client    valkey.Client
	keys      valkeycache.Keys
	lockTTL   time.Duration
	lockRenew time.Duration
}

// EnableValkey wires v into c so FetchIndex/FetchSources share upstream data
// with other debproxy replicas through it instead of each independently
// re-polling. Call once at startup; without it, IndexCache behaves exactly
// as it did before Valkey support existed.
func (c *IndexCache) EnableValkey(v valkey.Client, keys valkeycache.Keys, lockTTL, lockRenewInterval time.Duration) {
	c.valkey = &valkeyBacking{client: v, keys: keys, lockTTL: lockTTL, lockRenew: lockRenewInterval}
}

// LayoutDataFresh reports whether some replica successfully fetched real
// data for os/codename within the last schedule.refresh interval (see
// valkeycache.Keys.LayoutFresh and MarkLayoutDataFresh). When true, that
// layout's upstream data can be trusted outright from Valkey (see
// Fetcher.AdoptFromValkeyOutright/AdoptSourcesFromValkeyOutright) rather than
// gated by each individual upstream's own Cache-Control-derived Expires,
// which mirrors that don't send caching headers default to a bare 5
// minutes -- far shorter than any real schedule.refresh interval, which
// otherwise forces a real upstream touch on nearly every call. This is
// deliberately a separate signal from RefreshClaim (which only the periodic
// refresher's own cycle sets, and which decides who does the full
// fetch+auto-update cycle, not whether data is fresh enough to trust): a
// layout's periodic-refresher slot can be delayed by up to a full
// schedule.refresh interval by its own per-layout seed offset, and this flag
// lets any replica's on-demand avail.Build (e.g. a cold-start /live request)
// establish freshness itself rather than waiting on that far-off slot.
// False (no error surfaced) if Valkey isn't enabled or the check itself
// fails -- callers fall back to the normal fetch/adopt path, which is
// always correct, just not always as cheap.
func (c *IndexCache) LayoutDataFresh(ctx context.Context, os, codename string) bool {
	if c.valkey == nil {
		return false
	}
	b := c.valkey
	n, err := b.client.Do(ctx, b.client.B().Exists().Key(b.keys.LayoutFresh(os, codename)).Build()).ToInt64()
	if err != nil {
		return false
	}
	return n > 0
}

// MarkLayoutDataFresh records that os/codename was just successfully
// refreshed for real, for ttl (the caller's own schedule.refresh interval).
// Call this only after a genuine real fetch succeeds -- never merely because
// LayoutDataFresh was already true -- so the freshness window always counts
// down from an actual validation point instead of being extended forever by
// callers that never re-check anything themselves. ttl <= 0 is a no-op
// (schedule.refresh disabled means there's no interval to bound trust by).
func (c *IndexCache) MarkLayoutDataFresh(ctx context.Context, os, codename string, ttl time.Duration) {
	if c.valkey == nil || ttl <= 0 {
		return
	}
	b := c.valkey
	if err := b.client.Do(ctx, b.client.B().Set().Key(b.keys.LayoutFresh(os, codename)).Value("1").Px(ttl).Build()).Error(); err != nil {
		slog.Warn("valkey: mark layout data fresh failed", "os", os, "codename", codename, "err", err)
	}
}

// valkeyPayload is the JSON-serializable mirror of indexCacheEntry's
// Release-side fields, stored at Keys.UpstreamMeta. archPkgs and srcs are
// stored under their own separate keys (Keys.UpstreamPkgs / Keys.UpstreamSrcs)
// since they're considerably larger and aren't always both needed at once.
type valkeyPayload struct {
	ETag    string
	LastMod string
	Expires time.Time
	Release *apt.Release
}

// adoptFromValkey reports whether Valkey has an unexpired entry for
// upstream+suite+component and, if so, populates the local cache from it and
// returns the resulting entry. archs is the set of architectures to load
// alongside the release/meta; a missing per-arch key is simply left absent
// from the result (the same sparse-map shape FetchIndex already produces
// when an upstream doesn't serve every configured arch).
func (c *IndexCache) adoptFromValkey(ctx context.Context, cacheKey, upstream, suite, component string, archs []string) (*indexCacheEntry, bool) {
	if c.valkey == nil {
		return nil, false
	}
	b := c.valkey

	meta, ok := b.getMeta(ctx, upstream, suite, component)
	if !ok {
		return nil, false
	}

	entry := &indexCacheEntry{
		etag:     meta.ETag,
		lastMod:  meta.LastMod,
		expires:  meta.Expires,
		release:  meta.Release,
		archPkgs: b.fetchArchPkgs(ctx, upstream, suite, component, archs),
	}
	c.store(cacheKey, entry)
	return entry, true
}

// adoptFromValkeyForComparison reads Valkey's copy for upstream+suite+
// component regardless of whether it's still fresh per Expires -- unlike
// adoptFromValkey, which only serves a copy Valkey itself still considers
// current. FetchIndex uses this as a conditional-GET (ETag/If-None-Match) and
// PDiff comparison basis when the local cache has nothing for this key --
// e.g. it was evicted once refreshLayoutGroup finished a previous cycle with
// it (see IndexCache.EvictUpstream) -- but Valkey's last-published copy is
// still structurally valid to diff against even though it's no longer fresh
// enough to serve outright. The result is deliberately NOT written back into
// the local cache: it's meant to be used for this one FetchIndex call and
// then discarded, not to restore permanent local residency.
func (c *IndexCache) adoptFromValkeyForComparison(ctx context.Context, upstream, suite, component string, archs []string) (*indexCacheEntry, bool) {
	if c.valkey == nil {
		return nil, false
	}
	b := c.valkey

	meta, ok := b.getMetaRaw(ctx, upstream, suite, component)
	if !ok {
		return nil, false
	}
	return &indexCacheEntry{
		etag:     meta.ETag,
		lastMod:  meta.LastMod,
		expires:  meta.Expires,
		release:  meta.Release,
		archPkgs: b.fetchArchPkgs(ctx, upstream, suite, component, archs),
	}, true
}

// adoptSrcsFromValkey is the Sources-index counterpart of adoptFromValkey.
func (c *IndexCache) adoptSrcsFromValkey(ctx context.Context, cacheKey, upstream, suite, component string) ([]apt.RawSrc, bool) {
	if c.valkey == nil {
		return nil, false
	}
	b := c.valkey

	meta, ok := b.getMeta(ctx, upstream, suite, component)
	if !ok {
		return nil, false
	}

	srcs, ok := b.fetchSrcs(ctx, upstream, suite, component)
	if !ok {
		// No srcs cached yet -- but if meta.Release itself confirms this
		// upstream/component lists no Sources index at all (see
		// releaseListsSources), that's already the fully confirmed answer,
		// not a sign nobody's checked yet.
		if meta.Release != nil && !releaseListsSources(meta.Release, component) {
			c.updateSrcs(cacheKey, meta.Release, nil)
			return nil, true
		}
		return nil, false // meta fresh but no srcs cached yet (no replica has fetched sources)
	}
	c.updateSrcs(cacheKey, meta.Release, srcs)
	return srcs, true
}

// adoptSrcsFromValkeyForComparison is adoptFromValkeyForComparison's Sources
// counterpart -- see its doc comment. Not written back into the local cache.
func (c *IndexCache) adoptSrcsFromValkeyForComparison(ctx context.Context, upstream, suite, component string) (*indexCacheEntry, bool) {
	if c.valkey == nil {
		return nil, false
	}
	b := c.valkey

	meta, ok := b.getMetaRaw(ctx, upstream, suite, component)
	if !ok {
		return nil, false
	}
	srcs, ok := b.fetchSrcs(ctx, upstream, suite, component)
	if !ok {
		// Same reasoning as adoptSrcsFromValkey: a confirmed-empty Release
		// is a resolved answer, not a miss.
		if meta.Release != nil && !releaseListsSources(meta.Release, component) {
			return &indexCacheEntry{srcsRelease: meta.Release, srcs: nil}, true
		}
		return nil, false
	}
	return &indexCacheEntry{srcsRelease: meta.Release, srcs: srcs}, true
}

// getMetaRaw reads upstream+suite+component's meta from Valkey without
// checking Expires -- callers decide what "fresh enough" means for their own
// purpose (getMeta below requires it still be fresh to serve outright;
// the *ForComparison adopters only need the content to be structurally
// present, not still fresh, since it's used as a diff/reuse basis rather
// than served as-is).
func (b *valkeyBacking) getMetaRaw(ctx context.Context, upstream, suite, component string) (*valkeyPayload, bool) {
	meta, ok, err := valkeycache.GetJSON[valkeyPayload](ctx, b.client, b.keys.UpstreamMeta(upstream, suite, component))
	if err != nil {
		slog.Warn("valkey: read upstream meta failed", "upstream", upstream, "err", err)
		return nil, false
	}
	return meta, ok
}

func (b *valkeyBacking) getMeta(ctx context.Context, upstream, suite, component string) (*valkeyPayload, bool) {
	meta, ok := b.getMetaRaw(ctx, upstream, suite, component)
	if !ok {
		return nil, false
	}
	if !time.Now().Before(meta.Expires) {
		return nil, false // Valkey's copy is stale too; caller must fetch for real.
	}
	return meta, true
}

// fetchArchPkgs MGETs archs' Packages data for upstream+suite+component.
// Missing archs are simply absent from the result. Returns nil if archs is
// empty or the MGET itself fails (logged; callers treat nil as "no per-arch
// data available," same as a cache miss).
func (b *valkeyBacking) fetchArchPkgs(ctx context.Context, upstream, suite, component string, archs []string) map[string][]apt.RawPkg {
	if len(archs) == 0 {
		return nil
	}
	pkgKeys := make([]string, len(archs))
	for i, arch := range archs {
		pkgKeys[i] = b.keys.UpstreamPkgs(upstream, suite, component, arch)
	}
	vals, err := b.client.Do(ctx, b.client.B().Mget().Key(pkgKeys...).Build()).ToArray()
	if err != nil {
		slog.Warn("valkey: mget upstream pkgs failed", "upstream", upstream, "err", err)
		return nil
	}
	archPkgs := make(map[string][]apt.RawPkg, len(archs))
	for i, v := range vals {
		str, err := v.ToString()
		if err != nil {
			continue // this arch not cached in valkey; leave it absent
		}
		var pkgs []apt.RawPkg
		if err := json.Unmarshal([]byte(str), &pkgs); err != nil {
			slog.Warn("valkey: decode upstream pkgs failed", "upstream", upstream, "arch", archs[i], "err", err)
			continue
		}
		archPkgs[archs[i]] = pkgs
	}
	return archPkgs
}

// fetchSrcs reads upstream+suite+component's Sources data from Valkey.
func (b *valkeyBacking) fetchSrcs(ctx context.Context, upstream, suite, component string) ([]apt.RawSrc, bool) {
	srcs, ok, err := valkeycache.GetJSON[[]apt.RawSrc](ctx, b.client, b.keys.UpstreamSrcs(upstream, suite, component))
	if err != nil {
		slog.Warn("valkey: read upstream srcs failed", "upstream", upstream, "err", err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return *srcs, true
}

// publishToValkey writes entry through to Valkey and notifies other
// replicas via pub/sub. Best-effort: failures are logged, not returned, since
// the local fetch already succeeded and the caller has valid data to serve
// regardless of whether the shared-cache write succeeds.
func (c *IndexCache) publishToValkey(ctx context.Context, upstream, suite, component string, entry *indexCacheEntry) {
	if c.valkey == nil {
		return
	}
	b := c.valkey

	payload := valkeyPayload{ETag: entry.etag, LastMod: entry.lastMod, Expires: entry.expires, Release: entry.release}
	if err := valkeycache.SetJSON(ctx, b.client, b.keys.UpstreamMeta(upstream, suite, component), payload); err != nil {
		slog.Warn("valkey: write upstream meta failed", "upstream", upstream, "err", err)
		return
	}

	for arch, pkgs := range entry.archPkgs {
		if err := valkeycache.SetJSON(ctx, b.client, b.keys.UpstreamPkgs(upstream, suite, component, arch), pkgs); err != nil {
			slog.Warn("valkey: write upstream pkgs failed", "upstream", upstream, "arch", arch, "err", err)
		}
	}
}

// publishSrcsToValkey writes srcs through to Valkey. Kept separate from
// publishToValkey since FetchIndex and FetchSources succeed independently,
// and each should be able to publish what it fetched without waiting on the
// other.
func (c *IndexCache) publishSrcsToValkey(ctx context.Context, upstream, suite, component string, srcs []apt.RawSrc) {
	if c.valkey == nil {
		return
	}
	b := c.valkey
	if err := valkeycache.SetJSON(ctx, b.client, b.keys.UpstreamSrcs(upstream, suite, component), srcs); err != nil {
		slog.Warn("valkey: write upstream srcs failed", "upstream", upstream, "err", err)
	}
}

// acquireFetchLock attempts to acquire the distributed fetch lock for
// upstream+suite+component, starting a background renew loop for as long as
// the lock is held. ok is false (nil error) when another replica already
// holds it -- the expected, common outcome, not a failure. The returned stop
// func must be called once the fetch (success or failure) is complete; it
// stops the renew loop and releases the lock. If Valkey coordination isn't
// enabled, ok is always false and stop is a no-op, so callers always fetch
// directly exactly as they did before Valkey support existed.
func (c *IndexCache) acquireFetchLock(ctx context.Context, upstream, suite, component string) (ok bool, stop func(), err error) {
	if c.valkey == nil {
		return false, func() {}, nil
	}
	b := c.valkey
	key := b.keys.FetchLock(upstream, suite, component)
	lock, acquired, err := valkeycache.AcquireLock(ctx, b.client, key, b.lockTTL)
	if err != nil {
		return false, func() {}, err
	}
	if !acquired {
		return false, func() {}, nil
	}
	// The lost channel from StartRenewing is intentionally not consumed: on
	// loss the worst case is another replica also fetching concurrently,
	// which is harmless (both write valid, last-write-wins data to Valkey
	// afterward) -- the same tolerance already established elsewhere in this
	// design for concurrent on-demand pull-through.
	_, stopRenew := lock.StartRenewing(ctx, b.lockTTL, b.lockRenew)
	return true, func() {
		stopRenew()
		if err := lock.Release(context.Background()); err != nil {
			slog.Warn("valkey: release fetch lock failed", "upstream", upstream, "err", err)
		}
	}, nil
}

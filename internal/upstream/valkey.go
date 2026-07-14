package upstream

import (
	"context"
	"encoding/json"
	"fmt"
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
// stored under their own separate keys (Keys.UpstreamPkgEntry/UpstreamPkgBucket
// / Keys.UpstreamSrcs) since they're considerably larger and aren't always
// both needed at once.
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

// fetchArchPkgs reads archs' Packages data for upstream+suite+component from
// Valkey. Missing archs are simply absent from the result. Each arch's
// bucket is walked via SSCAN and its entries read via chunked MGET (see
// bucket.go), so no single reply is ever unbounded by the arch's total
// package count -- some buckets (e.g. Ubuntu's "universe" component) run to
// tens of thousands of packages, which is exactly what used to produce a
// multi-hundred-MB single MGET reply here.
func (b *valkeyBacking) fetchArchPkgs(ctx context.Context, upstream, suite, component string, archs []string) map[string][]apt.RawPkg {
	if len(archs) == 0 {
		return nil
	}
	archPkgs := make(map[string][]apt.RawPkg, len(archs))
	for _, arch := range archs {
		pkgs, err := b.fetchOneArchPkgs(ctx, upstream, suite, component, arch)
		if err != nil {
			slog.Warn("valkey: read upstream pkgs failed", "upstream", upstream, "arch", arch, "err", err)
			continue // this arch not cached in valkey; leave it absent
		}
		if pkgs != nil {
			archPkgs[arch] = pkgs
		}
	}
	return archPkgs
}

// fetchOneArchPkgs reads one arch's bucket in full, via a paginated SSCAN of
// its membership followed by chunked MGETs of the entries. Returns (nil, nil)
// if the bucket is empty/uncached -- distinct from a real error, both of
// which callers treat as "no cached data for this arch."
func (b *valkeyBacking) fetchOneArchPkgs(ctx context.Context, upstream, suite, component, arch string) ([]apt.RawPkg, error) {
	bucket := b.keys.UpstreamPkgBucket(upstream, suite, component, arch)
	members, err := scanBucketMembers(ctx, b.client, bucket)
	if err != nil {
		return nil, fmt.Errorf("scan bucket: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}

	pkgs := make([]apt.RawPkg, 0, len(members))
	for i := 0; i < len(members); i += upstreamPkgBatchSize {
		batch := members[i:min(i+upstreamPkgBatchSize, len(members))]
		entryKeys := make([]string, 0, len(batch))
		for _, m := range batch {
			pkg, version, ok := splitUpstreamPkgMember(m)
			if !ok {
				continue
			}
			entryKeys = append(entryKeys, b.keys.UpstreamPkgEntry(upstream, suite, component, arch, pkg, version))
		}
		if len(entryKeys) == 0 {
			continue
		}
		vals, err := b.client.Do(ctx, b.client.B().Mget().Key(entryKeys...).Build()).ToArray()
		if err != nil {
			return nil, fmt.Errorf("mget pkg entries: %w", err)
		}
		for _, v := range vals {
			str, err := v.ToString()
			if err != nil {
				continue // entry vanished between SSCAN and MGET (e.g. concurrent write); skip
			}
			var pkg apt.RawPkg
			if err := json.Unmarshal([]byte(str), &pkg); err != nil {
				return nil, fmt.Errorf("decode pkg entry: %w", err)
			}
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, nil
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
		if err := b.publishArchPkgs(ctx, upstream, suite, component, arch, pkgs); err != nil {
			slog.Warn("valkey: write upstream pkgs failed", "upstream", upstream, "arch", arch, "err", err)
		}
	}
}

// publishArchPkgs writes pkgs for upstream+suite+component+arch as a delta
// against whatever's currently in the bucket: only new/changed
// package+version entries are written and only stale ones removed, so a
// PDiff-driven update -- which typically changes a handful of packages out
// of tens of thousands -- never rewrites the whole arch. This is the write
// side of the same problem fetchOneArchPkgs's read side solves: the old
// one-blob-per-arch scheme meant every publish, even one triggered by a tiny
// PDiff, rewrote the complete arch as a single value.
//
// A member already in the bucket set is NOT assumed to still have valid
// entry data behind it -- see verifyExistingMembers below. That assumption
// broke in production: an operational purge deleted every up:/up-pkg: key
// (Release metadata and entry data) but not up-pkgs: (the bucket sets),
// leaving every member "already present" per the set while its entry data
// was gone. The diff below skipped writing all of them, since it only
// compares set membership -- a real fetch's result kept being silently
// discarded for anything that hadn't changed version, with no error and no
// self-healing. The same desync isn't purge-specific either: an MSET
// succeeding but a process dying before the paired SADD (or the reverse
// order elsewhere) reaches the server produces the identical inconsistency
// without anyone touching Valkey by hand.
func (b *valkeyBacking) publishArchPkgs(ctx context.Context, upstream, suite, component, arch string, pkgs []apt.RawPkg) error {
	bucket := b.keys.UpstreamPkgBucket(upstream, suite, component, arch)

	current, err := scanBucketMembers(ctx, b.client, bucket)
	if err != nil {
		return fmt.Errorf("scan current bucket: %w", err)
	}
	currentSet := make(map[string]bool, len(current))
	for _, m := range current {
		currentSet[m] = true
	}

	newSet := make(map[string]bool, len(pkgs))
	byMember := make(map[string]apt.RawPkg, len(pkgs))
	for _, pkg := range pkgs {
		m := upstreamPkgMember(pkg.Package, pkg.Version)
		newSet[m] = true
		byMember[m] = pkg
	}

	var toAdd, toRemove, unchanged []string
	for m := range newSet {
		if !currentSet[m] {
			toAdd = append(toAdd, m)
		} else {
			unchanged = append(unchanged, m)
		}
	}
	for m := range currentSet {
		if !newSet[m] {
			toRemove = append(toRemove, m)
		}
	}

	missing, err := b.findMembersMissingEntries(ctx, upstream, suite, component, arch, unchanged)
	if err != nil {
		return fmt.Errorf("verify existing pkg entries: %w", err)
	}
	toAdd = append(toAdd, missing...)

	for i := 0; i < len(toAdd); i += upstreamPkgBatchSize {
		batch := toAdd[i:min(i+upstreamPkgBatchSize, len(toAdd))]
		mset := b.client.B().Mset().KeyValue()
		n := 0
		for _, m := range batch {
			pkg, version, ok := splitUpstreamPkgMember(m)
			if !ok {
				continue
			}
			data, err := json.Marshal(byMember[m])
			if err != nil {
				return fmt.Errorf("encode pkg entry: %w", err)
			}
			mset = mset.KeyValue(b.keys.UpstreamPkgEntry(upstream, suite, component, arch, pkg, version), string(data))
			n++
		}
		if n > 0 {
			if err := b.client.Do(ctx, mset.Build()).Error(); err != nil {
				return fmt.Errorf("mset pkg entries: %w", err)
			}
		}
		if err := b.client.Do(ctx, b.client.B().Sadd().Key(bucket).Member(batch...).Build()).Error(); err != nil {
			return fmt.Errorf("sadd bucket members: %w", err)
		}
	}

	for i := 0; i < len(toRemove); i += upstreamPkgBatchSize {
		batch := toRemove[i:min(i+upstreamPkgBatchSize, len(toRemove))]
		if err := b.client.Do(ctx, b.client.B().Srem().Key(bucket).Member(batch...).Build()).Error(); err != nil {
			return fmt.Errorf("srem bucket members: %w", err)
		}
		entryKeys := make([]string, 0, len(batch))
		for _, m := range batch {
			pkg, version, ok := splitUpstreamPkgMember(m)
			if !ok {
				continue
			}
			entryKeys = append(entryKeys, b.keys.UpstreamPkgEntry(upstream, suite, component, arch, pkg, version))
		}
		if len(entryKeys) > 0 {
			if err := b.client.Do(ctx, b.client.B().Del().Key(entryKeys...).Build()).Error(); err != nil {
				return fmt.Errorf("del stale pkg entries: %w", err)
			}
		}
	}

	return nil
}

// findMembersMissingEntries checks members (bucket-set members the diff in
// publishArchPkgs considers unchanged, so it would otherwise never touch
// them again) and returns the subset whose UpstreamPkgEntry key doesn't
// actually exist -- see publishArchPkgs's doc comment for why this
// assumption can't be trusted on set membership alone. Chunked MGET, same
// batch size as every other bulk operation in this file, so verifying a
// large bucket is never one unbounded reply.
func (b *valkeyBacking) findMembersMissingEntries(ctx context.Context, upstream, suite, component, arch string, members []string) ([]string, error) {
	var missing []string
	for i := 0; i < len(members); i += upstreamPkgBatchSize {
		batch := members[i:min(i+upstreamPkgBatchSize, len(members))]
		entryKeys := make([]string, 0, len(batch))
		checked := make([]string, 0, len(batch))
		for _, m := range batch {
			pkg, version, ok := splitUpstreamPkgMember(m)
			if !ok {
				continue
			}
			entryKeys = append(entryKeys, b.keys.UpstreamPkgEntry(upstream, suite, component, arch, pkg, version))
			checked = append(checked, m)
		}
		if len(entryKeys) == 0 {
			continue
		}
		vals, err := b.client.Do(ctx, b.client.B().Mget().Key(entryKeys...).Build()).ToArray()
		if err != nil {
			return nil, fmt.Errorf("mget pkg entries: %w", err)
		}
		for j, v := range vals {
			if _, err := v.ToString(); err != nil {
				missing = append(missing, checked[j])
			}
		}
	}
	return missing, nil
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

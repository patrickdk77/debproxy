package valkeycache

// Keys builds prefixed Valkey key names for debproxy's shared cache. Every
// key group that a single Lua script reads/writes together wraps its shared
// grouping fields in an extra "{...}" hash tag, so Valkey Cluster places
// them on the same slot -- see the "Valkey key schema" section of the design
// doc for the full reasoning and an example.
type Keys struct {
	// Prefix is prepended to every key (e.g. "debproxy:"). Empty is valid.
	Prefix string
}

func (k Keys) upstreamTag(upstream, suite, component string) string {
	return "{" + upstream + ":" + suite + ":" + component + "}"
}

// UpstreamMeta is the HASH of etag/last_modified/expires/release_sha256 for
// one upstream+suite+component, mirroring upstream.indexCacheEntry.
func (k Keys) UpstreamMeta(upstream, suite, component string) string {
	return k.Prefix + "up:" + k.upstreamTag(upstream, suite, component) + ":meta"
}

func (k Keys) upstreamPkgTag(upstream, suite, component, arch string) string {
	return "{" + upstream + ":" + suite + ":" + component + ":" + arch + "}"
}

// UpstreamPkgEntry is the JSON-encoded apt.RawPkg for one package+version
// parsed from upstream+suite+component+arch's Packages file. Per-entry
// (rather than one blob per arch) so a PDiff-driven update writes only the
// handful of packages that actually changed, and so no single read/write
// ever has to move an entire arch's data (some buckets, e.g. Ubuntu's
// "universe" component, run to tens of thousands of packages and multiple
// hundred MB as one value) in a single request.
func (k Keys) UpstreamPkgEntry(upstream, suite, component, arch, pkg, version string) string {
	return k.Prefix + "up-pkg:" + k.upstreamPkgTag(upstream, suite, component, arch) + ":" + pkg + ":" + version
}

// UpstreamPkgBucket is the SET of "{package}:{version}" members present in
// upstream+suite+component+arch's most recently fetched Packages file,
// mirroring valkeystore's PkgBucket. Walked via SSCAN (never SMEMBERS) so
// enumerating it is also never one unbounded reply.
func (k Keys) UpstreamPkgBucket(upstream, suite, component, arch string) string {
	return k.Prefix + "up-pkgs:" + k.upstreamPkgTag(upstream, suite, component, arch)
}

// UpstreamSrcs holds the JSON-encoded parsed apt.RawSrc list.
func (k Keys) UpstreamSrcs(upstream, suite, component string) string {
	return k.Prefix + "up:" + k.upstreamTag(upstream, suite, component) + ":srcs"
}

// FetchLock is the distributed lock guarding upstream fetches for one
// upstream+suite+component. Shares its hash tag with the availability cache
// keys above since acquire-then-read-cache is the common path.
func (k Keys) FetchLock(upstream, suite, component string) string {
	return k.Prefix + "lock:fetch:" + k.upstreamTag(upstream, suite, component)
}

func (k Keys) pkgTag(os, codename, component, arch string) string {
	return "{" + os + ":" + codename + ":" + component + ":" + arch + "}"
}

// PkgEntry is the HASH of model.IndexEntry fields for one package+version.
func (k Keys) PkgEntry(os, codename, component, arch, pkg, version string) string {
	return k.Prefix + "pkg:" + k.pkgTag(os, codename, component, arch) + ":" + pkg + ":" + version
}

// PkgBucket is the SET of "{package}:{version}" members for one bucket.
func (k Keys) PkgBucket(os, codename, component, arch string) string {
	return k.Prefix + "pkgs:" + k.pkgTag(os, codename, component, arch)
}

// PkgLatest is the HASH of package -> highest known version for one bucket,
// maintained by a compare-and-set script alongside PkgEntry (same hash tag).
func (k Keys) PkgLatest(os, codename, component, arch string) string {
	return k.Prefix + "pkg-latest:" + k.pkgTag(os, codename, component, arch)
}

func (k Keys) srcTag(os, codename, component string) string {
	return "{" + os + ":" + codename + ":" + component + "}"
}

// SrcEntry is the HASH of model.SourceEntry fields for one package+version.
func (k Keys) SrcEntry(os, codename, component, pkg, version string) string {
	return k.Prefix + "src:" + k.srcTag(os, codename, component) + ":" + pkg + ":" + version
}

// SrcBucket is the SET of "{package}:{version}" members for one bucket.
func (k Keys) SrcBucket(os, codename, component string) string {
	return k.Prefix + "srcs:" + k.srcTag(os, codename, component)
}

// SrcLatest is the HASH of package -> highest known version for one bucket.
func (k Keys) SrcLatest(os, codename, component string) string {
	return k.Prefix + "src-latest:" + k.srcTag(os, codename, component)
}

// BucketsIndex is the global SET of every "{os}:{codename}:{component}:{arch}"
// combination that has ever had a package entry, so an empty-selector
// ListEntries can enumerate every bucket without a cluster-wide SCAN.
func (k Keys) BucketsIndex() string { return k.Prefix + "buckets:index" }

// BucketsSrc is the source-entry counterpart of BucketsIndex.
func (k Keys) BucketsSrc() string { return k.Prefix + "buckets:src" }

// UpstreamState is the HASH replacing model.UpstreamPackageState.
func (k Keys) UpstreamState(upstream, pkg, arch string) string {
	return k.Prefix + "upstate:" + upstream + ":" + pkg + ":" + arch
}

// BucketsUpstate is the global SET of every "{upstream}:{package}:{arch}"
// tuple that has ever had a state recorded, so all upstream states can be
// enumerated (e.g. for a full backup) without a cluster-wide SCAN -- the
// same reasoning as BucketsIndex/BucketsSrc.
func (k Keys) BucketsUpstate() string { return k.Prefix + "buckets:upstate" }

// PkgByDigest is the point-lookup index backing EntryByDigest.
func (k Keys) PkgByDigest(sha256 string) string {
	return k.Prefix + "pkg-by-digest:" + sha256
}

// RefreshClaim is the SET NX PX claim key one replica holds for the duration
// of schedule.refresh after refreshing one (os, codename) layout's upstream
// indexes (see cmd/debproxy's runLayoutRefreshLoop). Every replica still
// wakes up on its own local schedule.refresh+jitter timer, but before doing
// the actual fetch/auto-update work it tries to claim this key first; if
// another replica already refreshed (and so already holds the claim) this
// interval, it skips entirely instead of redundantly repeating the same
// upstream fetches and auto-update pulls. Letting the TTL expire naturally,
// rather than releasing it early, is intentional: expiry is what marks the
// layout due for its next refresh, whichever replica's timer notices first.
func (k Keys) RefreshClaim(os, codename string) string {
	return k.Prefix + "refresh-claim:" + os + ":" + codename
}

// LayoutFresh is a plain marker key (SET with a PX TTL, no NX) meaning "some
// replica successfully fetched real data for this (os, codename) layout
// within the last schedule.refresh interval" -- see
// upstream.IndexCache.LayoutDataFresh/MarkLayoutDataFresh. Unlike
// RefreshClaim, which only the periodic refresher's own cycle sets (it's a
// mutex deciding who does the full fetch+auto-update cycle), this key is set
// by *any* successful real fetch, including one triggered by an on-demand
// avail.Build (e.g. a cold-start /live request) -- so a layout doesn't have
// to wait for the periodic refresher's own, potentially far-off scheduled
// slot (its per-layout seed offset can delay the very first cycle by up to a
// full schedule.refresh interval) before other replicas' avail.Build calls
// can start trusting Valkey outright. Only ever set after a genuine real
// fetch, never just because the flag was already valid -- otherwise trust
// could extend forever without anything actually re-validating upstream.
func (k Keys) LayoutFresh(os, codename string) string {
	return k.Prefix + "layout-fresh:" + os + ":" + codename
}

// MetadataFlushClaim is the SET NX PX claim key one replica holds for the
// duration of schedule.metadata_flush after saving one (os, codename)
// layout's metadata (see cmd/debproxy's saveLayoutMetadata). Other replicas
// whose own refresh cycle finds this key already held skip the save
// entirely, so a multi-replica deployment doesn't have every replica
// redundantly re-pull and re-write the same layout's metadata every
// interval. Letting the TTL expire naturally, rather than releasing it early,
// is intentional: expiry is what marks the layout due for its next save.
func (k Keys) MetadataFlushClaim(os, codename string) string {
	return k.Prefix + "meta-flush-claim:" + os + ":" + codename
}

// OperationLock is the distributed lock (see AcquireLock) serializing
// debproxy's mutating admin operations -- snapshot, cleanup, update, rebuild,
// prime -- against each other and across every replica, since all of them
// touch the shared index/pool state and running two concurrently risks a
// logically-inconsistent snapshot. Used by both the /api HTTP surface and
// the periodic snapshot/cleanup schedulers (internal/api's operationRunner
// and OpLock).
func (k Keys) OperationLock() string { return k.Prefix + "lock:operation" }

// Job is the TTL'd key an async /api admin operation's status (queued,
// running, succeeded, or failed) is written to, so a status poll landing on
// any replica behind a load balancer can read the result of a job that ran
// on a different one. See internal/api's jobStore.
func (k Keys) Job(id string) string { return k.Prefix + "job:" + id }

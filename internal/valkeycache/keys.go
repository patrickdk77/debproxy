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

// UpstreamPkgs holds the JSON-encoded parsed apt.RawPkg list for one arch.
func (k Keys) UpstreamPkgs(upstream, suite, component, arch string) string {
	return k.Prefix + "up:" + k.upstreamTag(upstream, suite, component) + ":pkgs:" + arch
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

func (k Keys) liveTag(os, codename string) string {
	return "{" + os + ":" + codename + "}"
}

// LiveMeta is the HASH of built_at/expiry/hashes_json for one os/codename's
// /live serving artifacts, mirroring server.liveEntry.
func (k Keys) LiveMeta(os, codename string) string {
	return k.Prefix + "live:" + k.liveTag(os, codename) + ":meta"
}

// LiveFile is one compressed serving artifact's raw bytes, keyed by its
// relative path within the layout (e.g. "main/binary-amd64/Packages.gz").
func (k Keys) LiveFile(os, codename, relpath string) string {
	return k.Prefix + "live:" + k.liveTag(os, codename) + ":files:" + relpath
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

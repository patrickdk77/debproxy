# Memory Usage

debproxy holds two categories of data in RAM: the upstream package cache (raw stanzas fetched from upstream mirrors) and the live cache (merged, compressed Packages files served to apt clients). At the reference configuration described below, total RSS sits around **4.8 GB** per instance -- see [Valkey-backed shared cache](#valkey-backed-shared-cache) below for how a multi-replica deployment avoids paying this cost once per replica.

## Upstream package cache

Every configured upstream is fetched and held in memory rather than in a database. At this scale RAM is cheaper and faster than a database server, and reading every package entry from storage on each update cycle to produce a new Packages file would incur prohibitive IOPS costs.

**Methodology note:** the table below counts each configured upstream *source* separately -- e.g. `ubuntu-main`, `ubuntu-updates`, `ubuntu-security`, and the three `ubuntu-ports-*` equivalents each contribute their own full package count for a given codename, even though most of that content overlaps between them (an `-updates`/`-security` pocket is a delta on top of the base suite, not a disjoint set). This is deliberate: it's what the Valkey-backed upstream mirror cache (`internal/upstream/valkey.go`) actually stores -- one bucket per `(upstream, suite, component, arch)`, never deduplicated against sibling upstreams. The final *merged, deduplicated* `/live` package count (what a client actually sees) is a different, much lower number, since it collapses all of a codename's upstream sources down to one winning version per package.

Figures below are a fresh measurement (2026-07-14) against the real upstream mirrors, for the 6 standard Ubuntu sources (`ubuntu-main`/`-updates`/`-security` + the 3 `ubuntu-ports-*` equivalents) and 4 standard Debian sources (`debian-main`/`-updates`/`-security`/`-backports`), across every configured component and architecture. **Excludes** Ubuntu ESM/Pro, PPAs, and third-party repos (MongoDB, Node.js, etc.) -- those add some further amount on top but are individually small (a 25-repo sample of the third-party ones totaled ~322 KB combined) and weren't re-measured here since ESM requires spending a real Pro-subscription credential to query.

| Codename | Upstream packages | Bytes |
|---|---:|---:|
| ubuntu/noble | 280,650 | 304.3 MB |
| ubuntu/jammy | 282,245 | 290.0 MB |
| ubuntu/focal | 264,091 | 249.0 MB |
| ubuntu/bionic | 285,591 | 271.2 MB |
| debian/trixie | 220,608 | 172.7 MB |
| debian/bookworm | 203,726 | 153.5 MB |
| **Total (excl. ESM/PPA/third-party)** | **1,536,911** | **~1.41 GB** |

Package stanzas average **1,050 bytes** (Ubuntu) and **806 bytes** (Debian) of in-memory text. Adding ESM/PPA/third-party sources on top of this table's totals brings the full catalog to somewhat above 1.41 GB.

The config used for this data includes four Ubuntu codenames (noble, jammy, focal, bionic) with x86 and ports upstreams, two Debian stable codenames (trixie, bookworm), plus (not separately re-measured) Ubuntu ESM/Pro on the LTS releases and various third-party repos.

## Live cache

When the live path is built (on startup and after each background refresh),
debproxy merges all upstreams for each `(codename, component, arch)` combo and
writes the result into memory as gzip and zstd compressed Packages files. These
are served directly to apt clients; plain (uncompressed) files are never stored.

Compressed sizes are derived from the merged stanza count:
- **gzip** at ~4.5x compression ratio
- **zstd** at ~5.5x compression ratio

The largest single cost is Ubuntu universe, which merges 80,000 to 107,000 packages from the base upstream alone, across four architecture files per codename.

| Codename | Plain equiv. | .gz | .zst |
|---|---:|---:|---:|
| ubuntu/noble | ~540 MB | ~120 MB | ~98 MB |
| ubuntu/bionic | ~540 MB | ~120 MB | ~98 MB |
| ubuntu/jammy | ~485 MB | ~108 MB | ~88 MB |
| ubuntu/focal | ~445 MB | ~99 MB | ~81 MB |
| debian/trixie | ~307 MB | ~68 MB | ~56 MB |
| debian/bookworm | ~300 MB | ~67 MB | ~55 MB |
| experimental + misc | ~11 MB | ~2 MB | ~2 MB |
| **Total** | **~2,628 MB** | **~584 MB** | **~478 MB** |

The live cache holds **~1.06 GB** (gz + zst combined). Plain bytes are never allocated as a single buffer; stanzas stream through an `io.MultiWriter` into both compressors simultaneously during generation.

## Summary

| Component | Size |
|---|---:|
| Upstream package cache | ~2.1 GB |
| Live cache (gz + zst) | ~1.1 GB |
| Go runtime, binary, other | ~1.6 GB |
| **Total** | **~4.8 GB** |

Reducing the number of active codenames has a roughly linear effect on both categories. Disabling a large Ubuntu codename (e.g. bionic) saves around 430 MB from the upstream cache and 220 MB from the live cache.

## Rebuild spike

During a background live cache rebuild the old and new entries coexist in memory until the swap completes. Peak usage is therefore steady state plus one additional live cache: ~4.8 GB + ~1.1 GB = ~5.9 GB. The old entry is dereferenced at swap and collected on the next GC cycle, so the spike is brief but real. Provision at least 6 GB to avoid OOM during a rebuild.

## Valkey-backed shared cache

Everything above describes one self-contained instance: every replica in a
multi-replica deployment independently fetches every upstream and independently
holds its own full copy of the upstream package cache and the live cache. Add a
second replica and both numbers double; the memory cost scales linearly with
replica count for no benefit, since every replica is redundantly doing and
storing the same thing.

Enabling `valkey:` (see `config.example.yaml`) moves both of these off the heap
of every debproxy process and into a shared Valkey/Redis deployment instead --
see [Optional Valkey-backed shared cache](design.md#optional-valkey-backed-shared-cache-multi-replica-deployments)
in the design doc for the full mechanism (distributed fetch lock, freshness
tracking, live-artifact pub/sub).

The rest of this document (upstream package cache, live cache, the ~4.8 GB
total) describes a **non-Valkey** instance. This section, by contrast, is
grounded in a **real measurement of an actual Valkey-enabled production
deployment**:

**Measured 2026-07-14, production, real config (4 Ubuntu codenames +
2 Debian codenames + ESM + PPAs + third-party repos, per `config.example.yaml`'s
reference layout):**

| | |
|---|---:|
| Valkey memory attributable to debproxy | ~3.1 GB |
| Valkey `mem_fragmentation_ratio` | 1.01 (healthy) |
| Each debproxy replica's own RSS, steady state | ~1 GB |
| Each debproxy replica's own RSS, during a rebuild | 3-4 GB |
| Upstream cache key count (`up-pkg`, individual entries) | 1,627,930 |

- **Valkey does NOT hold the live cache at all.** The live cache (compressed
  gz/zst Packages files served to apt clients) exists only in each replica's
  own local memory (`Server.liveCache`); replicas share a *freshly-built* one
  via direct peer-to-peer HTTP fetch plus a small Valkey pub/sub notice (see
  `liveUpdatedMsg` in `internal/server/valkey.go`) -- the file content itself
  never goes through Valkey. What Valkey *does* hold is the upstream package
  cache (per-upstream-source, undeduplicated -- see the methodology note
  above) plus the pool metadata index (`internal/metadata/valkeystore`,
  tracking packages actually downloaded into local pool storage via
  pull-through/auto-update -- sized by how much of the catalog has actually
  been fetched, not the full upstream catalog size, and starts small on a
  fresh deployment or after a pool GC).
- **Each debproxy replica's own memory usage is ~1 GB, steady state.**
  A replica that finds Valkey's copy fresh adopts it directly (a handful of Valkey round trips) rather than
  fetching from upstream and parsing/compressing locally, and evicts its own
  local copy of an upstream's data once a refresh cycle is done with it
  (`IndexCache.EvictUpstream`) instead of holding every upstream's stanzas
  resident for the life of the process.
- **Except during a rebuild action -- measured at 3-4 GB.** Whenever a
  replica is the one actually doing real work -- the periodic background
  refresh for a layout, or an on-demand `/live` build that can't adopt a
  fresh copy from Valkey (cold start with nothing cached yet, or Valkey's
  copy has expired) -- that replica must hold the full merged data resident
  to parse and (for `/live`) compress it, the same as the non-Valkey path.
  Memory on that one replica temporarily rises to **3-4 GB measured**
  (below the non-Valkey per-instance figure, since only the one layout being
  rebuilt is resident, not every configured layout at once), then drops back
  to the ~1 GB steady state once the result is evicted/adopted-from-Valkey
  again. Provision each replica for the **measured rebuild-spike figure
  (4 GB)**, not the ~1 GB typical figure, so an in-progress rebuild on any
  one replica doesn't OOM it.

Net effect for an N-replica deployment: without Valkey, total memory is
roughly `N x 4.8 GB`. With Valkey, it's roughly `~3.1 GB (Valkey, debproxy's
share) + N x 1 GB` in steady state, with each replica still provisioned for
its own ~4 GB rebuild spike.

## Configuration recommendations

### Debian only (trixie + bookworm + experimental)

| Component | Size |
|---|---:|
| Upstream package cache | ~657 MB |
| Live cache (gz + zst) | ~250 MB |
| Go runtime, binary, other | ~1.6 GB |
| **Steady state** | **~2.5 GB** |
| **Rebuild spike** | **~2.75 GB** |

Debian packages average ~1,200 bytes per stanza and the live cache is small because Debian has no universe component. Provision **3 GB** to comfortably cover the rebuild spike with headroom for GC lag.

### Ubuntu only (noble + jammy)

| Component | Size |
|---|---:|
| Upstream package cache | ~735 MB |
| Live cache (gz + zst) | ~414 MB |
| Go runtime, binary, other | ~1.6 GB |
| **Steady state** | **~2.75 GB** |
| **Rebuild spike** | **~3.2 GB** |

Ubuntu universe is the dominant cost; noble and jammy each carry 240,000 to 280,000 upstream packages at ~1,400 bytes per stanza, and the live cache is larger than Debian's due to universe generating four architecture files per codename. Provision **3.5 GB** to cover the rebuild spike with headroom for GC lag.

### Full reference config (all codenames)

Provision **6 GB** as documented in the rebuild spike section above.

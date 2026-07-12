# Memory Usage

debproxy holds two categories of data in RAM: the upstream package cache (raw stanzas fetched from upstream mirrors) and the live cache (merged, compressed Packages files served to apt clients). At the reference configuration described below, total RSS sits around **4.8 GB** per instance -- see [Valkey-backed shared cache](#valkey-backed-shared-cache) below for how a multi-replica deployment avoids paying this cost once per replica.

## Upstream package cache

Every configured upstream is fetched and held in memory rather than in a database. At this scale RAM is cheaper and faster than a database server, and reading every package entry from storage on each update cycle to produce a new Packages file would incur prohibitive IOPS costs. The table below shows package counts from a full refresh cycle, one row per codename, summed across all its upstreams, suites, and components.

| Codename | Upstream packages |
|---|---:|
| debian/trixie | 256,906 |
| debian/bookworm | 238,981 |
| debian/experimental | 9,099 |
| ubuntu/bionic | 310,849 |
| ubuntu/focal | 286,745 |
| ubuntu/jammy | 281,618 |
| ubuntu/noble | 243,725 |
| **Total** | **1,628,119** |

Package stanzas average roughly 1,300 bytes of in-memory text (Ubuntu stanzas run ~1,400 bytes, Debian ~1,200). Upstream cache would occupy around **2.1 GB**.

The config used for this data includes four Ubuntu codenames (noble, jammy, focal, bionic) with x86 and ports upstreams, Ubuntu ESM/Pro on the LTS releases, two Debian stable codenames (trixie, bookworm), Debian experimental, and third-party repos for MongoDB and Node.js.

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
tracking, live-artifact pub/sub). The practical memory effect:

- **Valkey's own memory usage is about the same as one non-Valkey debproxy
  instance's total** -- ~4.8 GB at the reference configuration above. It is
  holding the same underlying data (parsed upstream stanzas plus compressed
  live artifacts); the difference is that it holds **one shared copy** instead
  of one copy per replica.
- **Each debproxy replica's own memory usage drops to roughly 1/8th** of the
  non-Valkey figure -- around **600 MB** at the reference configuration,
  instead of ~4.8 GB. A replica that finds Valkey's copy fresh adopts it
  directly (a handful of Valkey round trips) rather than fetching from
  upstream and parsing/compressing locally, and evicts its own local copy of
  an upstream's data once a refresh cycle is done with it
  (`IndexCache.EvictUpstream`) instead of holding every upstream's stanzas
  resident for the life of the process.
- **Except during a rebuild action.** Whenever a replica is the one actually
  doing real work -- the periodic background refresh for a layout, or an
  on-demand `/live` build that can't adopt a fresh copy from Valkey (cold
  start with nothing cached yet, or Valkey's copy has expired) -- that
  replica must hold the full merged data resident to parse and (for `/live`)
  compress it, the same as the non-Valkey path. Memory on that one replica
  temporarily approaches the non-Valkey per-instance figures above for the
  duration of that rebuild, then drops back to the ~1/8th steady state once
  the result is evicted/adopted-from-Valkey again. Provision each replica for
  the **non-Valkey steady-state figure**, not the ~600 MB typical figure, so an
  in-progress rebuild on any one replica doesn't OOM it.

Net effect for an N-replica deployment: without Valkey, total memory is
roughly `N x 4.8 GB`. With Valkey, it's roughly `4.8 GB (Valkey) + N x 600 MB`
in steady state, with each replica still provisioned to absorb its own
rebuild spike.

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

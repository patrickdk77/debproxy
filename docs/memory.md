# Memory Usage

debproxy holds two categories of data in RAM: the upstream package cache (raw stanzas fetched from upstream mirrors) and the live cache (merged, compressed Packages files served to apt clients). At the reference configuration described below, total RSS sits around **4.8 GB**.

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

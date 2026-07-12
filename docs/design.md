# Design Decisions

## The metadata index is persistent but rebuildable

An apt repository is already a self-describing structure: a signed `Release` file
points to `Packages` indices by hash, and each `Packages` entry points to a `.deb`
by `Filename` and hash. The metadata index therefore stores only what saves us from
re-parsing every file on each update:

- The file inventory: name, version, arch, sha256, pool path.
- The parsed dependency graph.
- Update provenance: which packages came from `auto_update` upstreams and what
  versions were last seen upstream.

The index is kept across snapshots and survives restarts. It is **fully rebuildable**
from the pool (plus a fresh upstream fetch for update state) via `debproxy rebuild`,
so losing it is not catastrophic, and swapping the storage format is low-risk.
There is no SQL database; the index lives in zstd-compressed deb822 files alongside
the pool.

When multiple instances run against the same storage backend, each instance merges
any changes written by others before flushing its own dirty state (merge-before-write),
and periodically re-reads files that have changed on disk (~hourly) so the in-memory
view stays consistent without requiring a full reload.

## Snapshots are static files, not database rows

Each update job writes a write-once, already-signed `dists/` tree under a
timestamped path (e.g. `2026-06-29/debian/dists/trixie/`). The path is immutable
once written; a snapshot is never modified, only superseded. `/current` is a small
alias file containing the current snapshot ID; `/{date}` resolves to the newest
snapshot with timestamp <= date by listing snapshot directories.

Because snapshot metadata is just files, they can be served by any static file
server or S3 bucket directly, with debproxy out of the loop. Only `/live` is
generated dynamically.

## Files keep their original names; dedup is by reference

`.deb` files are stored once under `pool/{os}/{codename}/{upstream}/...` using the
original Debian path and filename (e.g.
`pool/debian/trixie/debian-security/main/a/apt/apt_2.6.1_amd64.deb`). Keying by
`{os}/{codename}/{upstream}` makes provenance explicit and lets an entire retired
codename be purged with one directory removal.

There is exactly one global `pool/` shared by all snapshots. Snapshot `dists/`
trees reference pool files by relative path in `Filename:` fields; they never copy
files.

Deduplication is layered:

- **Content-level (primary):** the index maps `sha256 -> canonical pool_path`. On
  ingest, if that hash is already known, the write is skipped and the first entry's
  pool path is used in the generated `Packages`. This deduplicates the same `.deb`
  offered by multiple upstreams and the same content under different names.
- **Path-level (within one upstream):** a package version maps to a stable path, so
  re-fetching is a no-op and every snapshot referencing it shares the one copy.
- **Conflict policy:** if different content arrives at an occupied pool path (e.g. an
  upstream rebuilds a version in place), the default is keep-first-wins and log. Each
  published snapshot's `Packages` already pins the exact hash it referenced, so
  existing snapshots are not affected.

## Upstream trust model

Nothing from an upstream is trusted or stored until it is verified end-to-end.

- **Signature (authenticity):** each upstream declares one or more public keys
  (`keys:` in config). When fetching an upstream suite, debproxy verifies its
  `InRelease` (inline-signed) or `Release` + `Release.gpg` (detached) against those
  keys before trusting any content. Keys are loaded and parsed at config load time,
  so a missing or corrupt keyring fails fast at startup.
- **Hash chain (integrity):** the verified `Release` lists SHA256 for every
  `Packages` index file; each downloaded index is checked against it. Each `Packages`
  entry lists SHA256 and size for every `.deb`; every downloaded `.deb` is checked
  before admission to the pool.
- **Trust boundary:** the digest computed on ingest must equal the
  upstream-declared digest, which must come from a signature-verified `Release`. A
  mismatch at any link is a hard failure -- the file is rejected and logged -- so
  corrupted or tampered downloads never enter `pool/` or a snapshot.

Both armored (`.asc`) and binary (`.gpg`) OpenPGP keyrings are accepted.

## Ubuntu split-archive layout

Ubuntu's `archive.ubuntu.com` serves only amd64 and i386. arm64 and other
non-x86 architectures are served from `ports.ubuntu.com/ubuntu-ports`. Both hosts
list all architectures in their `Release` files but only serve a subset of the
corresponding `Packages` files.

Debproxy handles this by supporting per-upstream `architectures:` overrides. Each
upstream definition can restrict which architectures it fetches, independently of
the layout-level architecture list. The x86 upstreams are given
`architectures: [amd64, i386, all]` and the ports upstreams are given
`architectures: [arm64, all]`. When a `Packages` file is listed in `Release` but
returns HTTP 404, debproxy logs a warning and treats that arch as empty for that
upstream rather than failing.

## Repository signing key publishing

Clients need debproxy's public key to verify the snapshots it signs.

The public key is derived from `signing.private_key` and published under `keys/`
in the storage root in both formats:

- `keys/debproxy.asc` / `keys/debproxy.gpg` -- the current signing key (stable
  name, rotates on key change; CDN cache: 1 day).
- `keys/{fingerprint}.asc` / `keys/{fingerprint}.gpg` -- keyed by OpenPGP
  fingerprint (uppercase hex). Fingerprint-named files are immutable; older
  snapshots signed with a retired key remain verifiable (CDN cache: 1 year,
  immutable).

Only public key material is ever written to the served tree; the private key stays
in `signing.private_key` and is never published.

Publishing happens automatically on `serve` startup and via `debproxy publish-key`.

## Optional Valkey-backed shared cache (multi-replica deployments)

Every debproxy instance is fully self-contained by default: it independently
fetches every configured upstream, independently holds the parsed result in
memory, and independently compresses its own copy of the `/live` serving
artifacts. Running N replicas behind a shared storage backend means N
redundant upstream fetches, N times the memory, and N times the compression
work for output that is byte-identical across replicas. Enabling `valkey:`
(see `config.example.yaml`) lets a cluster of replicas share that work
instead through a common Valkey/Redis deployment -- see
[memory.md](memory.md#valkey-backed-shared-cache) for the resulting memory
profile. This is entirely optional and additive: with `valkey.enabled` unset,
every code path below is a no-op and debproxy behaves exactly as it did
before Valkey support existed.

Three distinct data sets move through Valkey, each independently:

- **Upstream availability cache** -- what a given upstream mirror currently
  has (parsed `Release`/`Packages`/`Sources`), keyed by upstream+suite+
  component. Feeds `avail.Build` and auto-update version comparisons.
- **Pool metadata index** -- what debproxy has actually pulled into its own
  pool. `internal/metadata/valkeystore` implements the same
  `metadata.MetadataIndex` interface as `deb822store` (see "The metadata
  index is persistent but rebuildable" above); `metadatafactory` picks one or
  the other based on `valkey.enabled`. A `debproxy rebuild` repopulates a
  valkeystore-backed index from the pool exactly as it does for deb822store.
- **Live serving artifacts** -- the final, merged, compressed, signed bytes
  for one `(os, codename)`'s `/live` view. This is the one thing that only
  ever existed in a single process's memory before Valkey support: a plain
  `map[string][]byte` per layout, rebuilt independently by every replica on
  its own TTL.

### Coordination mechanisms

- **Distributed fetch lock** (`lock:fetch:{upstream:suite:component}`, Valkey
  `SET NX PX` with a renew loop): only one replica fetches a given upstream
  at a time. A replica that loses the race serves its own stale data (or
  falls through and fetches anyway if it has nothing at all) rather than
  blocking on the lock -- availability wins over strict single-fetcher
  exclusivity.
- **Freshness trust, not just TTL adoption.** A per-upstream Valkey copy is
  normally only served outright while still fresh per that upstream's own
  (often absent, defaulting to a bare 5 minute) `Cache-Control`. That's far
  shorter than any real `schedule.refresh` interval, so on its own it would
  still force a real upstream touch on nearly every call. `LayoutFresh` is a
  separate, per-layout flag set only after a genuine real fetch succeeds
  (`IndexCache.MarkLayoutDataFresh`, TTL'd to `schedule.refresh`); while it's
  set, every upstream feeding that layout is trusted outright from Valkey
  regardless of its own `Cache-Control`, via
  `Fetcher.AdoptFromValkeyOutright`/`AdoptSourcesFromValkeyOutright`. A
  confirmed **absence** of data is just as trustworthy as its presence: if a
  cached `Release` itself proves an upstream serves none of the configured
  architectures, or lists no Sources index at all, that is a permanent fact
  about that upstream, not "not yet checked" -- it's adopted outright rather
  than triggering a real fetch that would only re-derive the same "nothing
  here" answer.
- **Pub/sub as an optimization only, never the source of truth.**
  `events:live-updated` notifies other replicas that a fresher compressed
  `/live` artifact is available so they can invalidate a local cache entry
  early rather than waiting out its own TTL. Valkey pub/sub is
  fire-and-forget: a replica that's offline or mid-restart simply misses
  the message, and its own next request or refresh cycle re-checks Valkey per
  the mechanisms above regardless, so a missed message costs at most one
  stale-TTL window, never a permanent miss.
- **Per-layout independent refresh scheduling.** Each `(os, codename)` layout
  runs its own refresh goroutine on its own jittered schedule (see
  `schedule.refresh`'s comment in `config.example.yaml`) rather than one
  global timer walking every layout in lockstep -- in a multi-replica
  deployment, a synchronized burst would mean every replica hammering every
  upstream's fetch lock at the same few moments. A `RefreshClaim` key (same
  `SET NX PX` shape as the fetch lock, TTL'd to the refresh interval) ensures
  only one replica actually does a given layout's refresh+auto-update cycle
  each interval; the others skip it, having already trusted `LayoutFresh`.

## HTTP caching headers

Responses carry `Cache-Control` headers matched to mutability:

| Path pattern | Cache-Control |
|---|---|
| `pool/**`, `keys/{fingerprint}.*`, `/{snapshot-id}/**` | `public, max-age=31536000, immutable` |
| `keys/debproxy.*` | `public, max-age=86400` |
| `/current/**`, `/live/**` | `public, max-age=300` |
| `metadata/**` (S3 only) | private, no cache |

The same values are set as S3 object metadata so direct-bucket and CloudFront
access gets correct headers without going through the debproxy HTTP server.
Filesystem files are created at mode `0644` (world-readable) via chmod-before-rename.

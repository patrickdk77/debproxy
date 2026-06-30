# Design Decisions

## The metadata index is disposable

An apt repository is already a self-describing structure: a signed `Release` file
points to `Packages` indices by hash, and each `Packages` entry points to a `.deb`
by `Filename` and hash. The metadata index therefore stores only what saves us from
re-parsing every file on each update:

- The file inventory: name, version, arch, sha256, pool path.
- The parsed dependency graph.
- Update provenance: which packages came from `auto_update` upstreams and what
  versions were last seen upstream.

The index is **fully rebuildable** from the pool (plus a fresh upstream fetch for
update state) via `debproxy rebuild`. This means losing the index is never
catastrophic, and swapping the storage format is low-risk. There is no SQL database;
the index lives in zstd-compressed deb822 files alongside the pool.

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

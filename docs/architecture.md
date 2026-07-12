# Architecture

## Component diagram

```mermaid
flowchart TD
  cfg["config.yaml"] --> factory["backend factories"]
  factory --> storage["storage backend"]
  factory --> meta["metadata index (persistent)"]
  storage --> pool["pool/{os}/{codename}/{upstream}/...\n(global, original names, ref-based dedup)"]
  storage --> pub["per-snapshot dists/\n(write-once signed metadata)"]
  storage --> mfiles["metadata/index/{os}/{codename}/{component}/{arch}.packages.zst"]
  pub -->|"Packages Filename -> pool/..."| pool
  meta --> deb822["deb822store (default)\n(in-memory + zstd files via storage backend)"]
  mfiles -.load on startup.-> deb822
  deb822 -.flush/commit.-> mfiles
  pool -.rebuild scan.-> meta
  meta -->|"sha256 -> canonical pool_path"| storage

  meta -.valkey.enabled instead of deb822store.-> valkeystore["valkeystore\n(pool metadata index)"]
  valkeystore --> vk["Valkey / Redis\n(optional shared cache, see design.md)"]
  upstream["upstream.IndexCache"] -.shared availability cache.-> vk
  livecache["server live cache"] -.shared compressed artifacts.-> vk
```

## Storage layout

Two namespaces share one storage root (filesystem directory or S3 prefix):

**`pool/`** -- global file store. One copy of each `.deb`, keyed by
`pool/{os}/{codename}/{upstream}/{section}/{letter}/{name}/{filename}`, preserving
the original Debian filename. Shared across all snapshots; never duplicated per
snapshot.

**`src/`** -- source package file store. One copy of each source file (`.dsc`,
`.orig.tar.*`, `.debian.tar.*`), keyed by
`src/{os}/{codename}/{upstream}/{component}/{letter}/{name}/{filename}`. Populated
on demand via pull-through; only present when `sources: true` is set on the
component layout and a client has requested source files.

**Per-snapshot `dists/`** -- write-once signed metadata only. Each snapshot lives
under `{snapshot-id}/{os}/dists/{codename}/`. `Packages` entries point at the global
pool via relative `Filename:` paths. `current/{os}` is a small text file containing
the current snapshot ID.

**`metadata/`** -- index files backing the in-memory deb822store:
`metadata/index/{os}/{codename}/{component}/{arch}.packages.zst` and
`metadata/upstream/{upstream}.state.zst`.

Example on-disk layout:

```
root/
  pool/debian/trixie/debian-security/main/a/apt/apt_2.6.1_amd64.deb
  src/debian/trixie/debian-main/main/a/apt/apt_2.6.1.dsc      # source file (pull-through)
  src/debian/trixie/debian-main/main/a/apt/apt_2.6.1.orig.tar.xz
  2026-06-29/debian/dists/trixie/InRelease
  2026-06-29/debian/dists/trixie/main/binary-amd64/Packages.gz
  2026-06-29/debian/dists/trixie/main/source/Sources.gz        # generated when sources: true
  current/debian                           # contains "2026-06-29"
  keys/debproxy.asc
  keys/ABCDEF1234....asc
  metadata/index/debian/trixie/main/amd64.packages.zst
  metadata/index/debian/trixie/main/sources.zst                # source entry metadata
  metadata/upstream/debian-main.state.zst
```

On S3 these are simply key prefixes within the configured bucket/prefix.

## URL routing

| URL pattern | Served by |
|---|---|
| `/live/{os}/{codename}/dists/...` | Dynamically generated, merged from all upstreams; cached in memory for 5 minutes |
| `/live/{os}/{codename}/pool/...` | Pool file with lazy pull-through from upstream |
| `/live/{os}/{codename}/src/...` | Source file with lazy pull-through from upstream (requires `sources: true`) |
| `/current/{os}/dists/...` | Resolves to newest published snapshot |
| `/{snapshot-id}/{os}/dists/...` | Reads from `{snapshot-id}/{os}/dists/...` in storage |
| `/{date}/{os}/dists/...` | Resolves to newest snapshot with timestamp <= date |
| `/{selector}/{os}/pool/...` | Pool file (no pull-through for pinned snapshots) |
| `/{selector}/{os}/src/...` | Source file (no pull-through for pinned snapshots) |
| `/keys/...` | Published signing key files |
| `/healthz` | Always 200 OK |

## Package layout

```
cmd/debproxy/main.go          -- CLI: serve, rebuild, update, snapshot, prime, publish-key, healthcheck
internal/
  apt/                        -- deb822 parse/write, Release parsing, Packages stanza builder, dep parser
  avail/                      -- merge upstreams per codename (highest version wins), dep closure
  config/config.go            -- typed config structs, Load(), env overrides, layout resolution, keyring load
  debversion/                 -- dpkg version comparison
  deb/                        -- .deb ar container reading (control.tar extraction)
  ingest/                     -- download + verify + store .deb, record IndexEntry
  metadata/
    metadata.go               -- MetadataIndex interface, Backuper (optional file-based backup capability)
    deb822store/store.go      -- in-memory index backed by zstd deb822 files; Flush/Refresh/merge-before-write
    valkeystore/              -- Valkey-backed MetadataIndex + Backup (writes deb822store's file layout)
  metadatafactory/factory.go  -- deb822store.Store, or valkeystore.Store when valkey.enabled
  model/model.go              -- domain types: Digest, Checksums, IndexEntry, UpstreamSource, Layout, ...
  publish/                    -- generate Packages (plain/gz/zst), Release, InRelease, Release.gpg
  rebuild/rebuild.go          -- scan pool/, parse .deb control, repopulate index
  server/
    server.go                 -- HTTP handler: snapshot/live/pool/keys routing, pull-through
    middleware.go             -- Apache Combined Log Format access logging, response compression
    valkey.go                 -- optional: adopt/publish compressed /live artifacts via Valkey
  signing/signing.go          -- load private key, sign/verify InRelease and Release.gpg, publish public key
  storage/
    storage.go                -- Storage interface (FileStore + Publisher)
    filesystem/fs.go          -- filesystem backend: atomic write, keep-first, chmod 0644
    s3store/s3.go             -- S3 backend: IfNoneMatch keep-first, ACL/Cache-Control/Content-Type per path
  storagefactory/factory.go   -- New(cfg) switch on storage.backend
  syncer/syncer.go            -- Prime, Update (auto_update refresh), Snapshot (publish + set current)
  upstream/
    fetch.go                  -- fetch + GPG-verify InRelease/Release, SHA256-verify Packages and .deb
    cache.go                  -- IndexCache: ETag/304 conditional re-fetch, Cache-Control expiry
    transport.go              -- tuned HTTP client, 3 retries on 5xx with idle-connection flush
    valkey.go                 -- optional: shared upstream availability cache, distributed fetch lock
  valkeycache/                -- optional: Valkey client wrapper, distributed lock, pub/sub, key naming (see design.md)
```

## Dependencies

All compression and cryptography runs in-process; no external binaries (`gpg`, `zstd`,
`xz` CLI) are ever invoked.

| Package | Purpose |
|---|---|
| `github.com/klauspost/compress` | gzip + zstd for generated indexes, metadata files, .deb control reading |
| `github.com/ProtonMail/go-crypto/openpgp` | load keyrings, verify InRelease/Release.gpg, sign snapshots |
| `github.com/blakesmith/ar` | read the `ar` container of `.deb` files during rebuild |
| `github.com/aws/aws-sdk-go-v2` | S3 storage backend |
| `github.com/valkey-io/valkey-go` | optional shared Valkey/Redis cache (see design.md) |
| `gopkg.in/yaml.v3` | config parsing |
| stdlib `log/slog` | structured application logging |

## Containerization

The binary is built statically (`CGO_ENABLED=0`) and runs on a minimal distroless
image as a non-root user.

```dockerfile
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/debproxy ./cmd/debproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/debproxy /usr/local/bin/debproxy
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["debproxy"]
CMD ["serve", "--config", "/etc/debproxy/config.yaml"]
```

## Kubernetes

Manifests live under `deploy/k8s/` and are applied with kustomize. Public keyrings
are non-sensitive and live in a ConfigMap; only the private signing key is in a Secret:

```
deploy/k8s/namespace.yaml   -- debproxy namespace
deploy/k8s/configmap.yaml   -- config.yaml at /etc/debproxy/config.yaml
deploy/k8s/keyrings.yaml    -- public upstream keyrings (ConfigMap) at /etc/debproxy/keys/
deploy/k8s/secret.yaml      -- private signing key (Secret) at /etc/debproxy/signing/
deploy/k8s/pvc.yaml         -- ReadWriteOnce volume at /var/lib/debproxy (filesystem backend)
deploy/k8s/deployment.yaml  -- single replica, liveness/readiness on /healthz, nonroot
deploy/k8s/service.yaml     -- ClusterIP on port 8080
deploy/k8s/ingress.yaml     -- ingress for apt clients
```

**Scaling** is two independent decisions:

1. **Storage backend** determines whether concurrent replicas can safely write
   to the pool at all. The filesystem backend with an RWO PVC requires
   `replicas: 1` and a `Recreate` update strategy -- only one node can mount
   it. To run more than one replica, switch to the S3 backend (no PVC, scales
   freely) or back the PVC with an RWX volume (NFS/EFS).
2. **`valkey.enabled`** (optional, orthogonal to the above) determines whether
   those replicas share upstream-fetch and `/live`-compression work instead of
   each doing it independently. Without it, N replicas behind S3/RWX works,
   but each one redundantly fetches every upstream and holds its own full
   memory footprint (see [memory.md](memory.md)) -- technically scalable, but
   each added replica costs as much upstream load and memory as the first.
   With it, replicas adopt each other's fetched data and compressed artifacts
   from Valkey, so adding replicas no longer multiplies upstream load or
   memory. See [design.md](design.md#optional-valkey-backed-shared-cache-multi-replica-deployments)
   for the mechanism.

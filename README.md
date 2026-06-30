# debproxy

CICD apt caching server, do not let your build fail from a connection issue, ubuntu ddos, server maintenance, or other problems.

Pull-through Debian/Ubuntu apt caching proxy with signed immutable snapshots.
Stores packages in a global pool (filesystem or S3); metadata is kept in
zstd-compressed deb822 files alongside the pool, no external database required.

See [docs/architecture.md](docs/architecture.md), [docs/design.md](docs/design.md), and [docs/todo.md](docs/todo.md) for architecture, design decisions, and implementation status.

## Quick start

```bash
go build -o debproxy ./cmd/debproxy
debproxy serve --config config.example.yaml
```

## Generating the repository signing key

debproxy signs every snapshot and `/live` index it publishes. You need a private
key in ASCII-armored OpenPGP format. Generate one with GnuPG:

```bash
gpg --batch --passphrase '' --quick-gen-key \
    'Debproxy Signing Key <apt@example.com>' rsa4096

# Export the private key (keep this secret)
gpg --armor --export-secret-keys apt@example.com \
    > /etc/debproxy/keys/debproxy-signing.asc

# Publish the derived public key into the storage root so apt clients can fetch it
debproxy publish-key --config /etc/debproxy/config.yaml
```

Point `signing.private_key` in your config at the exported `.asc` file.
Clients add the public key with:

```bash
curl http://debproxy-host/keys/debproxy.asc | sudo tee /etc/apt/trusted.gpg.d/debproxy.asc
```

## Upstream verification keys

Each upstream must list one or more public keys under `keys:`. Both
ASCII-armored (`.asc`) and binary (`.gpg`) keyrings are accepted.

For Debian, download the archive keyring:

```bash
apt-get install -y debian-archive-keyring
cp /usr/share/keyrings/debian-archive-keyring.gpg /etc/debproxy/keys/
```

For Ubuntu:

```bash
apt-get install -y ubuntu-keyring
cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /etc/debproxy/keys/
```

## Subcommands

| Command | Description |
|---|---|
| `serve` | Start the HTTP server (`:8080`). Publishes signing public key on startup. |
| `prime` | Seed the cache with a named package and its dependency closure, then snapshot. |
| `update` | Refresh all `auto_update` upstreams, pull newer versions, snapshot. |
| `snapshot` | Publish an immutable signed snapshot of the current cache state. |
| `rebuild` | Repopulate the metadata index by scanning the pool directory. |
| `publish-key` | Write the signing public key files into the storage root. |
| `healthcheck` | Check whether the running server is healthy (exits 0 on 200 OK). |

## Configuration

Copy `config.example.yaml` and adjust `storage`, `upstreams`, and `layouts`.

Environment overrides use the form `DEBPROXY_<SECTION>_<KEY>`:

```
DEBPROXY_STORAGE_BACKEND=s3
DEBPROXY_STORAGE_FILESYSTEM_ROOT=/data/debproxy
```

## Docker Compose

```bash
# Copy and edit the example config
cp deploy/etc/debproxy/config.yaml.example deploy/etc/debproxy/config.yaml

# First-time setup: publish the signing public key
docker compose run --rm publish-key

# Seed initial packages
docker compose run --rm prime

# Start the server
docker compose up -d debproxy

# Periodic updates (run from cron or a systemd timer)
docker compose run --rm update
```

## Kubernetes

Example manifests are under `deploy/k8s/`. Public keyrings live in the
ConfigMap; only the private signing key is in the Secret.

Fill in the placeholder values before applying:

```bash
# 1. Add public keyrings (armor with: gpg --armor --export ...)
#    Edit deploy/k8s/keyrings.yaml — replace REPLACE_ME under
#    debian-archive-keyring.gpg and ubuntu-archive-keyring.gpg

# 2. Create the Secret from the example (private signing key only)
cp deploy/k8s/secret.example.yaml secret.yaml
# edit secret.yaml — fill in debproxy-signing.asc
kubectl apply -f secret.yaml

# 3. Apply everything else
kubectl apply -k deploy/k8s/
```

## apt client setup

First, fetch the debproxy public signing key:

```bash
curl -fsSO http://debproxy-host/keys/debproxy.asc
sudo install -o root -g root -m 644 debproxy.asc /etc/apt/trusted.gpg.d/debproxy.asc
```

Then create a `.sources` file (deb822 format, used by Debian trixie+ and Ubuntu 24.04+):

```
# /etc/apt/sources.list.d/debproxy.sources
Types: deb
URIs: http://debproxy-host/current/debian
Suites: trixie
Components: main contrib non-free non-free-firmware
Signed-By: /etc/apt/trusted.gpg.d/debproxy.asc
```

Or pin to a specific snapshot date:

```
# /etc/apt/sources.list.d/debproxy.sources
Types: deb
URIs: http://debproxy-host/2026-06-01/debian
Suites: trixie
Components: main contrib non-free non-free-firmware
Signed-By: /etc/apt/trusted.gpg.d/debproxy.asc
```

## Replacing the upstream mirrors with debproxy

The recommended setup is to **replace** the official mirror entries with debproxy
rather than adding it alongside them. Debproxy's `/live` endpoint serves the
union of all configured upstreams and fetches uncached packages on demand, so it
is functionally equivalent to pointing directly at the upstream mirrors.

Remove or disable `/etc/apt/sources.list` and any existing files under
`/etc/apt/sources.list.d/`, then add a single debproxy `.sources` file. Use
`/current` for the latest published snapshot (reproducible, immutable) or `/live`
for a dynamic view that always reflects what is available upstream.

If you intentionally keep both debproxy and the official mirrors, apt will see the
same packages from two sources. Raise debproxy's priority with a pin file so it
wins when both offer the same version:

```
# /etc/apt/preferences.d/debproxy
Package: *
Pin: origin debproxy-host
Pin-Priority: 900
```

`Pin: origin` matches the **hostname** of the source URL (not the Release
`Origin:` field). Priority 900 beats the default mirrors (500) but stays below
1000, so apt will still upgrade from the upstream mirror if a newer version is
available there that debproxy has not yet cached.

To verify the priorities in effect:

```bash
apt-cache policy <package>
```

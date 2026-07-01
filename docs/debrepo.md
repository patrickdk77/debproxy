# debrepo

`debrepo` is a standalone command-line tool that generates signed apt repository
metadata from `.deb` files stored on disk. It requires no configuration file; all
parameters are supplied via flags. State is persisted per component as a
zstd-compressed deb822 file so subsequent runs only reprocess changes.

It is separate from the main `debproxy` daemon and is intended for managing
first-party package repositories that are not mirrored from an upstream.

## Usage

```
debrepo -key <path> -dir <repo-root> -os <name> [-origin <s>] [-label <s>] [-force]
```

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `-key` | yes | Path to an armored OpenPGP private signing key |
| `-dir` | yes | Path to the repository root (debrepo reads/writes under `dists/` inside it) |
| `-os` | yes | OS name used in Release metadata (e.g. `ubuntu`, `debian`). Supports `{codename}`. |
| `-origin` | no | Release `Origin` field (defaults to the value of `-os`). Supports `{codename}`. |
| `-label` | no | Release `Label` field (defaults to the value of `-os`). Supports `{codename}`. |
| `-force` | no | Discard saved state and reprocess all packages from scratch. |

## Directory layout

`debrepo` expects the following layout under the repo root passed to `-dir`:

```
<repo-root>/          <-- pass this to -dir
  dists/
    <codename>/
      <component>/
        deb/
          *.deb              <-- .deb files may be at any depth under deb/
          subdir/
            *.deb
        source/
          *.dsc              <-- source packages may be at any depth under source/
          *.orig.tar.*
          *.debian.tar.*
          Sources            <-- written by debrepo (if .dsc files are present)
          Sources.gz         <-- written by debrepo
          Sources.xz         <-- written by debrepo
          Sources.zst        <-- written by debrepo
        binary-<arch>/       <-- create to declare supported architectures
          Packages           <-- written by debrepo
          Packages.gz        <-- written by debrepo
          Packages.xz        <-- written by debrepo
          Packages.zst       <-- written by debrepo
        .debrepo.zst         <-- binary state (written by debrepo)
        .debrepo-src.zst     <-- source state (written by debrepo, if source/ exists)
        .debrepo.old.zst     <-- previous binary state (fallback)
        .debrepo-src.old.zst <-- previous source state (fallback)
  pool/
    <component>/
      <letter>/
        <package>/
          *.deb              <-- pool .deb files are included in every codename
      .debrepo.zst           <-- pool binary state (written by debrepo)
```

## What debrepo generates

For each `<codename>` found under `dists/`, debrepo writes:

- `dists/<codename>/<component>/binary-<arch>/Packages` (plain, .gz, .xz, .zst)
- `dists/<codename>/<component>/source/Sources` (plain, .gz, .xz, .zst)  -- only
  written for components that contain at least one `.dsc` file
- `dists/<codename>/Release`
- `dists/<codename>/InRelease` (inline-signed)
- `dists/<codename>/Release.gpg` (detached signature)

Plain `Packages`/`Sources` files are written alongside compressed variants so the
repository can be served by any standard webserver without special decompression
middleware.

## Architecture discovery

Supported architectures for a suite are determined by two sources:

1. Subdirectories named `binary-<arch>` within any component directory.
2. The `Architecture` field of each `.deb` processed (excluding `arch=all`).

Packages with `Architecture: all` are included in every architecture index.

## Incremental operation

On each run, debrepo loads the saved state for each component and reconciles it
against the `.deb` files currently present under `deb/` (recursively):

- Entries for `.deb` files that have been deleted are removed from state.
- New `.deb` files not present in state are parsed and added.
- Files whose size or modification time has changed since the last run are
  reprocessed and their state entry updated.
- Unchanged files are not re-read.

State is written atomically: the current `.debrepo.zst` is renamed to
`.debrepo.old.zst` before the new state is written. On load failure the old
file is used as a fallback.

Pass `-force` to discard all saved state and reprocess every package from
scratch. This rewrites the state files unconditionally and is useful after
moving files or recovering from a corrupted state.

## Signing key

The `-key` flag accepts an armored OpenPGP private key file (the same format
as `gpg --armor --export-secret-keys`). The corresponding public key must be
distributed to clients separately (e.g. placed under `keys/` in the web root)
so that apt can verify the repository.

## Example

```sh
# Generate (or refresh) metadata for all codenames under /srv/repo/dists/
debrepo \
  -key /etc/apt-repo/signing.asc \
  -dir /srv/repo \
  -os myorg \
  -origin "MyOrg Packages" \
  -label myorg
```

After running, configure an apt source on clients
(`/etc/apt/sources.list.d/myorg.sources`):

```
Types: deb
URIs: https://repo.example.com/
Suites: <codename>
Components: <component>
Signed-By: /etc/apt/trusted.gpg.d/myorg.gpg
```

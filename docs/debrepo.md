# debrepo

`debrepo` is a standalone command-line tool that generates signed apt repository
metadata from `.deb` files stored on disk or in an S3 bucket. It requires no
configuration file; all parameters are supplied via flags. State is persisted
per component as a zstd-compressed deb822 file so subsequent runs only
reprocess changes.

It is separate from the main `debproxy` daemon and is intended for managing
first-party package repositories that are not mirrored from an upstream.

## Usage

```
debrepo -key <path> -dir <repo-root> -os <name> [-origin <s>] [-label <s>] [-force]
        [-s3-region <r>] [-s3-endpoint <url>] [-s3-path-style] [-s3-no-acl]
```

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `-key` | yes | Path to an armored OpenPGP private signing key |
| `-dir` | yes | Repository root: a directory, or `s3://[key:secret@]bucket/prefix` (debrepo reads/writes under `dists/` inside it) |
| `-os` | yes | OS name used in Release metadata (e.g. `ubuntu`, `debian`). Supports `{codename}`. |
| `-origin` | no | Release `Origin` field (defaults to the value of `-os`). Supports `{codename}`. |
| `-label` | no | Release `Label` field (defaults to the value of `-os`). Supports `{codename}`. |
| `-force` | no | Discard saved state and reprocess all packages from scratch. |
| `-s3-region` | no | Region of an `s3://` repository. Defaults to `AWS_REGION`, `AWS_DEFAULT_REGION`, then the shared config. |
| `-s3-endpoint` | no | Endpoint URL of an `s3://` repository, for S3-compatible stores. |
| `-s3-path-style` | no | Use path-style addressing for an `s3://` repository. |
| `-s3-no-acl` | no | Set no object ACL on written objects. Needed for buckets with ACLs disabled or public ACLs blocked. |

## Repositories in S3

With `-dir s3://bucket/prefix`, debrepo reads the same layout from the
bucket and writes its output back as objects. The access key pair comes
from `key:secret@` in the URL, taken literally (write a `/` inside the
secret as `%2F`), or from the AWS default credential chain when the URL has
none. A secret in the URL is part of the command line, which other users
on the machine can read in the process list and which shell history and
job logs keep; the credential chain (environment, shared config, instance
role) avoids that. The credentials need `s3:ListBucket`, `s3:GetObject`
and `s3:PutObject` on the bucket, plus `s3:PutObjectAcl` unless
`-s3-no-acl` is set.

S3 has no directories, so debrepo takes one listing of the prefix at the
start of a run and treats every key below a path as that path's contents.
To declare an architecture, upload any object under
`dists/<codename>/<component>/binary-<arch>/`, such as a zero-byte key with
that name and a trailing slash; after the first run the Packages files
serve as the marker.

Change detection uses each object's size and LastModified in place of the
mtime. A new or changed `.deb` is downloaded once to a temporary file to
read its control paragraph and checksums. A file the listing returned but
the bucket would not deliver (a read denied by policy, a failed download)
aborts that codename and the run exits non-zero, rather than publishing a
signed index without the package; the same holds for an unreadable file or
directory on disk. A file that is not a valid `.deb` is skipped with a
warning, as before. The state files are objects next
to the indexes; because S3 has no rename, the previous state is copied to
`.old.zst` rather than moved, and the metadata set is written index files
first and InRelease after Release, not as one atomic group. Objects under
`dists/` are written with the public-read ACL (unless `-s3-no-acl`) and
`Cache-Control: public, max-age=720`; the pool state file keeps the pool
default, which only debrepo itself reads. Keys that do not clean to
themselves (a `//`, a `.` or `..` segment) are ignored with a warning,
since a read of such a key would go to the cleaned path.

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

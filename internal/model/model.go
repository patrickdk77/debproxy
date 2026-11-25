package model

import (
	"fmt"
	"github.com/debproxy/debproxy/internal/apt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Digest is a hex-encoded hash digest.
type Digest string

func (d Digest) String() string { return string(d) }

// Checksums holds the SHA-2 digests we store for every pool file.
type Checksums struct {
	SHA256 Digest
	SHA512 Digest
}

// UpstreamSource is a fully resolved upstream for a specific layout context.
type UpstreamSource struct {
	Name  string
	URL   string
	Suite string
	// Component lists the upstream's own real component division(s) to fetch
	// from, e.g. ["main"] or ["main", "contrib"] -- matching apt's own
	// Components: field, which has always accepted more than one. Each is
	// tried independently against the upstream's Release; one not being
	// listed there is not an error, just nothing to merge in from it (see
	// releaseServedArchs/releaseListsSources). This is independent of the
	// layout's own Component (see Layout), which is just the name packages
	// from every configured upstream get merged and published under.
	Component  []string
	Archs      []string
	AutoUpdate bool
	// FetchSources enables pull-through of deb-src (source package) requests for
	// this upstream within the component it was resolved for.
	FetchSources bool
	VerifyKeys   openpgp.EntityList
	// Username and Password are used for HTTP Basic Auth (e.g. Ubuntu ESM/Pro).
	// Leave empty for unauthenticated upstreams.
	Username string
	Password string
	// Network forces fetches from this upstream over a specific IP family:
	// "ipv4", "ipv6", or "" for the process-wide default (config's top-level
	// upstream_network, itself "" for standard dual-stack behavior). Resolved
	// from this upstream's own config (falling back to the global default)
	// during config loading, so by the time a Fetcher sees it, it's already
	// this upstream's final, effective value -- no further fallback needed.
	Network string
	// S3 holds the connection settings for an s3:// URL. Unused for http
	// and https upstreams. For an s3:// upstream Username and Password
	// carry the access key id and secret access key; both empty means the
	// AWS default credential chain.
	S3 S3Options
	// Filter restricts which packages this upstream may contribute. nil
	// allows every package the upstream lists.
	Filter *PackageFilter
}

// S3Options selects the S3 endpoint an s3:// upstream is read from. Empty
// fields take the AWS SDK's own defaults.
type S3Options struct {
	Region         string
	Endpoint       string
	ForcePathStyle bool
}

// Identity names the connection the options describe, for cache and dedup
// keys: the same s3://bucket/prefix reached through two endpoints is two
// repositories. Empty for an http upstream.
func (o S3Options) Identity() string {
	return o.Endpoint + "\x00" + o.Region
}

// PackageFilter decides by package name which packages an upstream may
// contribute. Allow and Deny are unanchored regular expressions; a name
// passes when it matches Allow (or Allow is nil) and does not match Deny
// (or Deny is nil).
type PackageFilter struct {
	Allow *regexp.Regexp
	Deny  *regexp.Regexp
}

// Allows reports whether a package with the given name passes the filter.
// A nil filter allows everything.
func (f *PackageFilter) Allows(name string) bool {
	if f == nil {
		return true
	}
	if f.Allow != nil && !f.Allow.MatchString(name) {
		return false
	}
	if f.Deny != nil && f.Deny.MatchString(name) {
		return false
	}
	return true
}

// ComponentKey joins Component into the single opaque string used wherever
// a component needs to identify a cache entry, Valkey key namespace, or map
// key -- "," is a safe, stable, order-preserving separator since apt
// component names never contain it.
func (u UpstreamSource) ComponentKey() string {
	return strings.Join(u.Component, ",")
}

// DedupKey returns a key identifying which upstream mirror u fetches from --
// URL, Suite, and Component together, since the same mirror can be resolved
// into more than one UpstreamSource (e.g. shared across components or
// layouts) but only needs fetching once. Name/Archs/etc. are deliberately
// excluded: they vary per resolved UpstreamSource without changing what's
// actually fetched from upstream.
func (u UpstreamSource) DedupKey() string {
	return u.URL + "\x00" + u.Suite + "\x00" + u.ComponentKey() + "\x00" + u.S3.Identity()
}

// Layout identifies a merged repository view: os / codename / component.
type Layout struct {
	OS        string
	Codename  string
	Component string
	Archs     []string
	// HashTypes lists the hash algorithms written to Release (e.g. "sha256",
	// "sha512", "sha1", "md5sum"). All components within a codename share the
	// same value; it is repeated here for convenient lookup.
	HashTypes []string
	Upstreams []UpstreamSource
}

// LayoutKey returns a stable string key for the layout.
func (l Layout) Key() string {
	return path.Join(l.OS, l.Codename, l.Component)
}

// Selector narrows index queries; empty fields match any value.
type Selector struct {
	OS        string
	Codename  string
	Component string
	Arch      string
	// Upstream, when set, is honored by FindSourceEntry to scope the lookup
	// to a specific upstream's record. Two upstreams commonly carry a source
	// package at the identical version at once (e.g. debian-main and
	// debian-security); an empty Upstream matches any. Ignored by
	// ListEntries/ListSourceEntries and the binary package lookups, which
	// have no need to disambiguate by upstream.
	Upstream string
}

// IndexEntry is one placement of a package within a layout (os/codename/
// component/arch). The same pool file (by SHA256) may have several entries when
// shared across components or upstreams.
type IndexEntry struct {
	OS             string
	Codename       string
	Component      string
	Arch           string
	Package        string
	Version        string
	Upstream       string
	FromAutoUpdate bool
	PoolPath       string
	Checksums      Checksums
	Size           int64
	// Control is the full deb822 Packages stanza (Filename normalized to PoolPath,
	// X-Debproxy-* fields excluded).
	Control   string
	FirstSeen time.Time
}

// UpstreamPackageState tracks last-known upstream version for update jobs.
type UpstreamPackageState struct {
	Upstream        string
	PackageName     string
	Arch            string
	UpstreamVersion string
	LastChecked     time.Time
}

// SourceFile is one file belonging to a source package.
type SourceFile struct {
	Filename string
	Size     int64
	MD5      Digest
	SHA1     Digest
	SHA256   Digest
	SHA512   Digest
}

func SourceFileFromRaw(f apt.RawSrcFile) SourceFile {
	return SourceFile{
		Filename: f.Filename,
		Size:     f.Size,
		MD5:      Digest(f.MD5),
		SHA1:     Digest(f.SHA1),
		SHA256:   Digest(f.SHA256),
		SHA512:   Digest(f.SHA512),
	}
}

func (f SourceFile) Hashes() apt.Hashes {
	return apt.Hashes{MD5: string(f.MD5), SHA1: string(f.SHA1), SHA256: string(f.SHA256), SHA512: string(f.SHA512)}
}

// SourceEntry records one source package's placement within a layout component.
type SourceEntry struct {
	OS        string
	Codename  string
	Component string
	Package   string
	Version   string
	Upstream  string
	// LocalDir is the storage directory for this source package's files:
	// src/{os}/{codename}/{upstream}/{component}/{letter}/{name}
	LocalDir string
	// UpstreamDir is the upstream's original Directory: field, used for pull-through.
	UpstreamDir string
	Files       []SourceFile
	// Stanza is the full deb822 Sources stanza with Directory: rewritten to LocalDir.
	Stanza    string
	FirstSeen time.Time
	// FilesDownloaded is true when at least one file for this source package
	// version has been stored locally. Only entries with this flag set are
	// eligible for auto-update downloads on a version bump.
	FilesDownloaded bool
}

// SourceDir returns the storage directory for a source package's files.
func SourceDir(osName, codename, upstreamName, component, name string) string {
	first := "_"
	if name != "" {
		first = strings.ToLower(name[:1])
	}
	return path.Join("src", osName, codename, upstreamName, component, first, name)
}

// SourceFilePath returns the storage path for a single source package file.
func SourceFilePath(osName, codename, upstreamName, component, name, filename string) string {
	return SourceDir(osName, codename, upstreamName, component, name) + "/" + filename
}

// PoolSection is the section segment of a pool path. Upstreams may publish
// a blank Section (the GitHub CLI repository does), and a blank segment
// cannot be addressed, so it becomes "misc".
func PoolSection(section string) string {
	section = strings.TrimSpace(section)
	if section == "" {
		return "misc"
	}
	return section
}

// PoolPath builds the storage path for a package under pool/{os}/{codename}/{upstream}/...
func PoolPath(os, codename, upstream, section, name, version, arch string) string {
	section = PoolSection(section)
	first := "_"
	if name != "" {
		first = strings.ToLower(name[:1])
	}
	debName := fmt.Sprintf("%s_%s_%s.deb", name, version, arch)
	return path.Join("pool", os, codename, upstream, section, first, name, debName)
}

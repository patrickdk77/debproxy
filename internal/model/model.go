package model

import (
	"fmt"
	"path"
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
	Name       string
	URL        string
	Suite      string
	Component  string
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
	SHA256   Digest
}

// SourceEntry records one source package's placement within a layout component.
type SourceEntry struct {
	OS          string
	Codename    string
	Component   string
	Package     string
	Version     string
	Upstream    string
	// LocalDir is the storage directory for this source package's files:
	// src/{os}/{codename}/{upstream}/{component}/{letter}/{name}
	LocalDir    string
	// UpstreamDir is the upstream's original Directory: field, used for pull-through.
	UpstreamDir string
	Files       []SourceFile
	// Stanza is the full deb822 Sources stanza with Directory: rewritten to LocalDir.
	Stanza      string
	FirstSeen   time.Time
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

// PoolPath builds the storage path for a package under pool/{os}/{codename}/{upstream}/...
func PoolPath(os, codename, upstream, section, name, version, arch string) string {
	section = strings.TrimSpace(section)
	if section == "" {
		section = "misc"
	}
	first := "_"
	if name != "" {
		first = strings.ToLower(name[:1])
	}
	debName := fmt.Sprintf("%s_%s_%s.deb", name, version, arch)
	return path.Join("pool", os, codename, upstream, section, first, name, debName)
}

// PackagesFilename returns the Filename field for a Packages index entry relative to archive root.
func PackagesFilename(poolPath string) string {
	return poolPath
}

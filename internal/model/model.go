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
	VerifyKeys openpgp.EntityList
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

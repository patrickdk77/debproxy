package valkeystore

import (
	"strings"

	"github.com/debproxy/debproxy/internal/model"
)

// pkgBucket identifies one (os, codename, component, arch) bucket.
type pkgBucket struct{ os, codename, component, arch string }

// srcBucket identifies one (os, codename, component) bucket. Sources are
// architecture-independent, matching model.Selector's Arch field being
// ignored for source lookups.
type srcBucket struct{ os, codename, component string }

func bucketKey(os, codename, component, arch string) string {
	return os + ":" + codename + ":" + component + ":" + arch
}

// splitBucketKey is the inverse of bucketKey. Assumes os/codename/component
// never contain ":" themselves -- the same assumption valkeycache.Keys
// already makes when joining these fields inside a hash tag.
func splitBucketKey(k string) (os, codename, component, arch string, ok bool) {
	parts := strings.SplitN(k, ":", 4)
	if len(parts) != 4 {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func srcBucketKeyStr(os, codename, component string) string {
	return os + ":" + codename + ":" + component
}

func splitSrcBucketKey(k string) (os, codename, component string, ok bool) {
	parts := strings.SplitN(k, ":", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// bucketMember is the SET member recording one upstream's package presence
// in a bucket. Split on the first TWO ":" only: Debian package names never
// contain ":" (policy restricts them to lowercase alphanumerics and +-.),
// and upstream names are config-defined identifiers that never contain ":"
// either, but versions frequently do (an epoch prefix like "2:1.4-1"), so
// splitting on the first two colons is exactly the upstream/package/version
// boundary regardless of how many further colons the version itself
// contains. Upstream leads the member (rather than trailing) so two
// upstreams sharing an identical package+version produce distinct members
// instead of colliding -- see PkgEntry/SrcEntry's doc comments for why this
// matters.
func bucketMember(upstream, pkg, version string) string {
	return upstream + ":" + pkg + ":" + version
}

func splitBucketMember(m string) (upstream, pkg, version string, ok bool) {
	parts := strings.SplitN(m, ":", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func pkgBucketMatches(sel model.Selector, os, codename, component, arch string) bool {
	if sel.OS != "" && sel.OS != os {
		return false
	}
	if sel.Codename != "" && sel.Codename != codename {
		return false
	}
	if sel.Component != "" && sel.Component != component {
		return false
	}
	if sel.Arch != "" && sel.Arch != arch {
		return false
	}
	return true
}

func srcBucketMatches(sel model.Selector, os, codename, component string) bool {
	if sel.OS != "" && sel.OS != os {
		return false
	}
	if sel.Codename != "" && sel.Codename != codename {
		return false
	}
	if sel.Component != "" && sel.Component != component {
		return false
	}
	return true
}

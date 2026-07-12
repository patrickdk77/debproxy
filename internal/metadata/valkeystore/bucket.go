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

// bucketMember is the SET member recording one package's presence in a
// bucket. Split on the FIRST ":" only: Debian package names never contain
// ":" (policy restricts them to lowercase alphanumerics and +-.), but
// versions frequently do (an epoch prefix like "2:1.4-1"), so splitting on
// the first colon is exactly the package/version boundary regardless of how
// many further colons the version itself contains.
func bucketMember(pkg, version string) string {
	return pkg + ":" + version
}

func splitBucketMember(m string) (pkg, version string, ok bool) {
	parts := strings.SplitN(m, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
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

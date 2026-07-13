package valkeycache

import (
	"strings"
	"testing"
)

func TestKeysUpstreamGroupSharesHashTag(t *testing.T) {
	k := Keys{Prefix: "debproxy:"}
	tag := "{ubuntu-main:noble:main}"

	for name, got := range map[string]string{
		"meta":       k.UpstreamMeta("ubuntu-main", "noble", "main"),
		"srcs":       k.UpstreamSrcs("ubuntu-main", "noble", "main"),
		"fetch_lock": k.FetchLock("ubuntu-main", "noble", "main"),
	} {
		if !strings.Contains(got, tag) {
			t.Errorf("%s key %q missing expected hash tag %q", name, got, tag)
		}
	}
}

// TestKeysUpstreamPkgGroupSharesHashTag covers UpstreamPkgEntry/UpstreamPkgBucket,
// which are scoped per-arch (upstream:suite:component:arch) rather than
// sharing UpstreamMeta's per-upstream:suite:component tag above -- each
// arch's package data is read/written independently (SSCAN/MGET/MSET/SADD/
// SREM/DEL never span more than one arch in a single command), so there's no
// need to force every arch plus meta onto one Cluster slot.
func TestKeysUpstreamPkgGroupSharesHashTag(t *testing.T) {
	k := Keys{Prefix: "debproxy:"}
	tag := "{ubuntu-main:noble:main:amd64}"

	entry := k.UpstreamPkgEntry("ubuntu-main", "noble", "main", "amd64", "curl", "8.0-1")
	bucket := k.UpstreamPkgBucket("ubuntu-main", "noble", "main", "amd64")

	for name, got := range map[string]string{"entry": entry, "bucket": bucket} {
		if !strings.Contains(got, tag) {
			t.Errorf("%s key %q missing expected hash tag %q", name, got, tag)
		}
	}
	if entry == bucket {
		t.Fatalf("upstream pkg keys must be distinct: entry=%q bucket=%q", entry, bucket)
	}

	other := k.UpstreamPkgBucket("ubuntu-main", "noble", "main", "arm64")
	if bucket == other {
		t.Fatalf("expected different arches to produce different buckets, both got %q", bucket)
	}
}

func TestKeysPkgGroupSharesHashTag(t *testing.T) {
	k := Keys{}
	tag := "{debian:trixie:main:amd64}"

	entry := k.PkgEntry("debian", "trixie", "main", "amd64", "curl", "8.0-1")
	bucket := k.PkgBucket("debian", "trixie", "main", "amd64")
	latest := k.PkgLatest("debian", "trixie", "main", "amd64")

	for name, got := range map[string]string{"entry": entry, "bucket": bucket, "latest": latest} {
		if !strings.Contains(got, tag) {
			t.Errorf("%s key %q missing expected hash tag %q", name, got, tag)
		}
	}
	if entry == bucket || entry == latest || bucket == latest {
		t.Fatalf("pkg keys must be distinct: entry=%q bucket=%q latest=%q", entry, bucket, latest)
	}
}

func TestKeysSrcGroupSharesHashTag(t *testing.T) {
	k := Keys{}
	tag := "{debian:trixie:main}"

	for name, got := range map[string]string{
		"entry":  k.SrcEntry("debian", "trixie", "main", "curl", "8.0-1"),
		"bucket": k.SrcBucket("debian", "trixie", "main"),
		"latest": k.SrcLatest("debian", "trixie", "main"),
	} {
		if !strings.Contains(got, tag) {
			t.Errorf("%s key %q missing expected hash tag %q", name, got, tag)
		}
	}
}

func TestKeysDifferentBucketsProduceDifferentTags(t *testing.T) {
	k := Keys{}
	a := k.PkgBucket("debian", "trixie", "main", "amd64")
	b := k.PkgBucket("debian", "trixie", "main", "arm64")
	if a == b {
		t.Fatalf("expected different arches to produce different keys, both got %q", a)
	}
}

func TestKeysPrefixIsHonored(t *testing.T) {
	withPrefix := Keys{Prefix: "debproxy:"}.BucketsIndex()
	withoutPrefix := Keys{}.BucketsIndex()
	if withPrefix != "debproxy:buckets:index" {
		t.Fatalf("got %q, want %q", withPrefix, "debproxy:buckets:index")
	}
	if withoutPrefix != "buckets:index" {
		t.Fatalf("got %q, want %q", withoutPrefix, "buckets:index")
	}
}

func TestKeysBucketsUpstate(t *testing.T) {
	got := Keys{Prefix: "debproxy:"}.BucketsUpstate()
	if got != "debproxy:buckets:upstate" {
		t.Fatalf("got %q, want %q", got, "debproxy:buckets:upstate")
	}
}

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
		"pkgs":       k.UpstreamPkgs("ubuntu-main", "noble", "main", "amd64"),
		"srcs":       k.UpstreamSrcs("ubuntu-main", "noble", "main"),
		"fetch_lock": k.FetchLock("ubuntu-main", "noble", "main"),
	} {
		if !strings.Contains(got, tag) {
			t.Errorf("%s key %q missing expected hash tag %q", name, got, tag)
		}
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

func TestKeysLiveGroupSharesHashTag(t *testing.T) {
	k := Keys{}
	tag := "{debian:trixie}"

	meta := k.LiveMeta("debian", "trixie")
	file := k.LiveFile("debian", "trixie", "main/binary-amd64/Packages.gz")

	if !strings.Contains(meta, tag) {
		t.Errorf("meta key %q missing expected hash tag %q", meta, tag)
	}
	if !strings.Contains(file, tag) {
		t.Errorf("file key %q missing expected hash tag %q", file, tag)
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

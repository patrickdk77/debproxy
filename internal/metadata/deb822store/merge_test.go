package deb822store

import (
	"sort"
	"testing"

	"github.com/debproxy/debproxy/internal/model"
)

func idxEntry(pkg, ver, up, pool string) model.IndexEntry {
	return model.IndexEntry{Package: pkg, Version: ver, Upstream: up, PoolPath: pool}
}

func srcEntry(pkg, ver, up, dir string) model.SourceEntry {
	return model.SourceEntry{Package: pkg, Version: ver, Upstream: up, LocalDir: dir}
}

func upstreamsOf(entries []model.IndexEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Upstream)
	}
	sort.Strings(out)
	return out
}

// TestMergeIndexEntriesKeepsBothUpstreamsAtSameVersion is the regression
// test for the data-loss bug: two upstreams carrying the identical
// version are two distinct entries with two distinct pool files, and the
// merge must preserve both.
func TestMergeIndexEntriesKeepsBothUpstreamsAtSameVersion(t *testing.T) {
	a := idxEntry("openssl", "3.0.15-1", "debian-main", "pool/debian/trixie/debian-main/o/openssl.deb")
	b := idxEntry("openssl", "3.0.15-1", "debian-security", "pool/debian/trixie/debian-security/o/openssl.deb")

	got := mergeIndexEntries([]model.IndexEntry{a, b}, []model.IndexEntry{a, b})
	if len(got) != 2 {
		t.Fatalf("merged %d entries, want 2: %+v", len(got), got)
	}
	ups := upstreamsOf(got)
	if ups[0] != "debian-main" || ups[1] != "debian-security" {
		t.Fatalf("upstreams %v, want both debian-main and debian-security", ups)
	}
	pools := map[string]bool{}
	for _, e := range got {
		pools[e.PoolPath] = true
	}
	if len(pools) != 2 {
		t.Fatalf("pool paths collapsed: %v", pools)
	}
}

// TestMergeIndexEntriesMemoryWinsForSameIdentity pins the pre-existing
// contract: for an identical (pkg, ver, upstream) the in-memory copy
// replaces the on-disk one.
func TestMergeIndexEntriesMemoryWinsForSameIdentity(t *testing.T) {
	disk := idxEntry("hello", "1.0", "main", "old-pool-path")
	mem := idxEntry("hello", "1.0", "main", "new-pool-path")

	got := mergeIndexEntries([]model.IndexEntry{disk}, []model.IndexEntry{mem})
	if len(got) != 1 {
		t.Fatalf("merged %d, want 1", len(got))
	}
	if got[0].PoolPath != "new-pool-path" {
		t.Errorf("disk entry won: %+v", got[0])
	}
}

func TestMergeIndexEntriesUnionOfDisjointSets(t *testing.T) {
	disk := idxEntry("a", "1", "u", "pa")
	mem := idxEntry("b", "1", "u", "pb")
	got := mergeIndexEntries([]model.IndexEntry{disk}, []model.IndexEntry{mem})
	if len(got) != 2 {
		t.Fatalf("merged %d, want 2", len(got))
	}
}

func TestMergeIndexEntriesEmptyInputs(t *testing.T) {
	if got := mergeIndexEntries(nil, nil); len(got) != 0 {
		t.Errorf("nil+nil -> %d entries", len(got))
	}
	one := []model.IndexEntry{idxEntry("a", "1", "u", "p")}
	if got := mergeIndexEntries(one, nil); len(got) != 1 {
		t.Errorf("disk only -> %d", len(got))
	}
	if got := mergeIndexEntries(nil, one); len(got) != 1 {
		t.Errorf("memory only -> %d", len(got))
	}
}

// TestMergeIndexEntriesDifferentVersionsSameUpstreamBothKept guards the
// other axis: the fix must not start collapsing distinct versions.
func TestMergeIndexEntriesDifferentVersionsSameUpstreamBothKept(t *testing.T) {
	v1 := idxEntry("hello", "1.0", "main", "p1")
	v2 := idxEntry("hello", "2.0", "main", "p2")
	got := mergeIndexEntries([]model.IndexEntry{v1}, []model.IndexEntry{v2})
	if len(got) != 2 {
		t.Fatalf("merged %d, want 2", len(got))
	}
}

func TestMergeSourceEntriesKeepsBothUpstreamsAtSameVersion(t *testing.T) {
	a := srcEntry("openssl", "3.0.15-1", "debian-main", "src/a")
	b := srcEntry("openssl", "3.0.15-1", "debian-security", "src/b")

	got := mergeSourceEntries([]model.SourceEntry{a, b}, []model.SourceEntry{a, b})
	if len(got) != 2 {
		t.Fatalf("merged %d, want 2", len(got))
	}
	dirs := map[string]bool{}
	for _, e := range got {
		dirs[e.LocalDir] = true
	}
	if !dirs["src/a"] || !dirs["src/b"] {
		t.Fatalf("one upstream's source entry was dropped: %v", dirs)
	}
}

func TestMergeSourceEntriesMemoryWinsForSameIdentity(t *testing.T) {
	disk := srcEntry("hello", "1.0", "main", "old")
	mem := srcEntry("hello", "1.0", "main", "new")
	got := mergeSourceEntries([]model.SourceEntry{disk}, []model.SourceEntry{mem})
	if len(got) != 1 || got[0].LocalDir != "new" {
		t.Fatalf("got %+v", got)
	}
}

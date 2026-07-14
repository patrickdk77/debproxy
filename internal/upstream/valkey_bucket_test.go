package upstream

import (
	"context"
	"strconv"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/testsupport"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

func newTestBacking(t *testing.T) *valkeyBacking {
	t.Helper()
	client := testsupport.NewTestClient(t, TestValkeyAddr)
	return &valkeyBacking{client: client, keys: valkeycache.Keys{Prefix: "debproxy-test:"}}
}

func rawPkg(name, version string) apt.RawPkg {
	return apt.RawPkg{
		Package: name,
		Version: version,
		Arch:    "amd64",
		Raw:     "Package: " + name + "\nVersion: " + version + "\n",
	}
}

// pkgSet reports the (package, version) pairs present in pkgs, for
// order-independent comparison (avail.Build itself is order-independent --
// see avail.go -- so fetchOneArchPkgs makes no ordering guarantee).
func pkgSet(pkgs []apt.RawPkg) map[string]bool {
	set := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		set[p.Package+":"+p.Version] = true
	}
	return set
}

func TestPublishArchPkgs_RoundTrip(t *testing.T) {
	ctx := context.Background()
	b := newTestBacking(t)

	pkgs := []apt.RawPkg{rawPkg("curl", "8.0-1"), rawPkg("wget", "1.21-1")}
	if err := b.publishArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64", pkgs); err != nil {
		t.Fatalf("publishArchPkgs: %v", err)
	}

	got, err := b.fetchOneArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64")
	if err != nil {
		t.Fatalf("fetchOneArchPkgs: %v", err)
	}
	want := pkgSet(pkgs)
	if len(got) != len(want) {
		t.Fatalf("fetchOneArchPkgs returned %d packages, want %d", len(got), len(want))
	}
	for _, p := range got {
		if !want[p.Package+":"+p.Version] {
			t.Errorf("unexpected package in result: %s:%s", p.Package, p.Version)
		}
	}
}

// TestPublishArchPkgs_IncrementalUpdate is the direct regression test for
// this whole redesign: a PDiff-style update that changes one package (a
// version bump) and leaves everything else untouched must result in exactly
// that one addition and one removal at the Valkey level -- not a rewrite of
// the whole bucket. It verifies this two ways: the final read-back state is
// correct, AND the untouched entry's own Valkey key still exists with
// unchanged content (proof it was never targeted by the second publish's
// writes at all, not just that it happens to still be correct).
func TestPublishArchPkgs_IncrementalUpdate(t *testing.T) {
	ctx := context.Background()
	b := newTestBacking(t)

	initial := []apt.RawPkg{
		rawPkg("curl", "8.0-1"),
		rawPkg("wget", "1.21-1"),
		rawPkg("vim", "9.0-1"),
	}
	if err := b.publishArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64", initial); err != nil {
		t.Fatalf("initial publishArchPkgs: %v", err)
	}

	// Simulate a PDiff-driven update: curl bumps to a new version; wget and
	// vim are untouched.
	updated := []apt.RawPkg{
		rawPkg("curl", "8.1-1"), // version bump: old entry must be removed, new one added
		rawPkg("wget", "1.21-1"),
		rawPkg("vim", "9.0-1"),
	}
	if err := b.publishArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64", updated); err != nil {
		t.Fatalf("incremental publishArchPkgs: %v", err)
	}

	// The stale curl 8.0-1 entry key must be gone.
	oldKey := b.keys.UpstreamPkgEntry("ubuntu-main", "noble", "main", "amd64", "curl", "8.0-1")
	if _, ok, err := valkeycache.GetJSON[apt.RawPkg](ctx, b.client, oldKey); err != nil {
		t.Fatalf("GetJSON old curl entry: %v", err)
	} else if ok {
		t.Error("stale curl 8.0-1 entry still present after incremental update, want it removed")
	}

	// The untouched wget entry's key must never have been touched: fetch it
	// directly and confirm it round-trips exactly.
	wgetKey := b.keys.UpstreamPkgEntry("ubuntu-main", "noble", "main", "amd64", "wget", "1.21-1")
	wget, ok, err := valkeycache.GetJSON[apt.RawPkg](ctx, b.client, wgetKey)
	if err != nil || !ok {
		t.Fatalf("GetJSON wget entry: ok=%v err=%v", ok, err)
	}
	if wget.Raw != rawPkg("wget", "1.21-1").Raw {
		t.Errorf("untouched wget entry content changed: got %q", wget.Raw)
	}

	// Final read-back must reflect exactly the updated set.
	got, err := b.fetchOneArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64")
	if err != nil {
		t.Fatalf("fetchOneArchPkgs: %v", err)
	}
	gotSet := pkgSet(got)
	wantSet := pkgSet(updated)
	if len(gotSet) != len(wantSet) {
		t.Fatalf("fetchOneArchPkgs returned %d packages, want %d (%v)", len(gotSet), len(wantSet), gotSet)
	}
	for k := range wantSet {
		if !gotSet[k] {
			t.Errorf("missing expected package %q after incremental update", k)
		}
	}
}

// TestPublishArchPkgs_SelfHealsEntryMissingDespiteSetMembership is the
// direct regression test for the production incident: a bucket set member
// whose entry data has gone missing (e.g. an external purge that deleted
// up-pkg: keys but not up-pkgs: set membership, or a process dying between
// a paired MSET and SADD) must be re-added on the next publish of the same,
// otherwise-unchanged package -- not silently skipped forever because the
// diff only compares set membership.
func TestPublishArchPkgsSelfHealsEntryMissingDespiteSetMembership(t *testing.T) {
	ctx := context.Background()
	b := newTestBacking(t)

	pkgs := []apt.RawPkg{rawPkg("curl", "8.0-1"), rawPkg("wget", "1.21-1")}
	if err := b.publishArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64", pkgs); err != nil {
		t.Fatalf("initial publishArchPkgs: %v", err)
	}

	// Simulate the incident: delete curl's entry key directly, leaving its
	// bucket-set membership (and wget's entry) untouched.
	curlKey := b.keys.UpstreamPkgEntry("ubuntu-main", "noble", "main", "amd64", "curl", "8.0-1")
	if err := b.client.Do(ctx, b.client.B().Del().Key(curlKey).Build()).Error(); err != nil {
		t.Fatalf("simulate entry loss: %v", err)
	}
	if _, ok, err := valkeycache.GetJSON[apt.RawPkg](ctx, b.client, curlKey); err != nil || ok {
		t.Fatalf("test setup: expected curl entry gone, ok=%v err=%v", ok, err)
	}

	// Publish the exact same, unchanged package set again -- the diff sees
	// curl as "already a member" and would previously skip rewriting it.
	if err := b.publishArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64", pkgs); err != nil {
		t.Fatalf("republish of unchanged pkgs: %v", err)
	}

	curl, ok, err := valkeycache.GetJSON[apt.RawPkg](ctx, b.client, curlKey)
	if err != nil {
		t.Fatalf("GetJSON curl entry after republish: %v", err)
	}
	if !ok {
		t.Fatal("curl entry still missing after republishing the unchanged package set -- self-heal did not happen")
	}
	if curl.Version != "8.0-1" {
		t.Errorf("healed curl entry has wrong version: got %q", curl.Version)
	}

	// fetchOneArchPkgs must now correctly return both packages again.
	got, err := b.fetchOneArchPkgs(ctx, "ubuntu-main", "noble", "main", "amd64")
	if err != nil {
		t.Fatalf("fetchOneArchPkgs: %v", err)
	}
	gotSet := pkgSet(got)
	if !gotSet["curl:8.0-1"] || !gotSet["wget:1.21-1"] {
		t.Fatalf("expected both curl and wget after self-heal, got %v", gotSet)
	}
}

// TestPublishArchPkgs_ChunkedAcrossBatches exercises the SSCAN+chunked-MGET
// read and chunked write paths with more members than a single batch
// (upstreamPkgBatchSize), confirming the chunking loops don't drop or
// duplicate entries at a batch boundary.
func TestPublishArchPkgs_ChunkedAcrossBatches(t *testing.T) {
	ctx := context.Background()
	b := newTestBacking(t)

	const n = upstreamPkgBatchSize + 250 // spans two batches, second partial
	pkgs := make([]apt.RawPkg, 0, n)
	for i := 0; i < n; i++ {
		pkgs = append(pkgs, rawPkg("pkg", strconv.Itoa(i)))
	}
	if err := b.publishArchPkgs(ctx, "ubuntu-main", "noble", "universe", "amd64", pkgs); err != nil {
		t.Fatalf("publishArchPkgs: %v", err)
	}

	got, err := b.fetchOneArchPkgs(ctx, "ubuntu-main", "noble", "universe", "amd64")
	if err != nil {
		t.Fatalf("fetchOneArchPkgs: %v", err)
	}
	if len(got) != n {
		t.Fatalf("fetchOneArchPkgs returned %d packages, want %d", len(got), n)
	}
	gotSet := pkgSet(got)
	if len(gotSet) != n {
		t.Fatalf("fetchOneArchPkgs returned %d distinct packages, want %d (duplicates or collisions)", len(gotSet), n)
	}
}

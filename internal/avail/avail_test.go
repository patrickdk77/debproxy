package avail_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/klauspost/compress/gzip"
	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/testsupport"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// testValkeyAddr is set by TestMain once the shared container is up.
var testValkeyAddr string

func TestMain(m *testing.M) {
	addr, stop, err := testsupport.StartValkey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "avail tests: %v\n", err)
		fmt.Fprintln(os.Stderr, "avail tests require Docker with access to pull "+testsupport.ValkeyImage)
		os.Exit(1)
	}
	testValkeyAddr = addr
	code := m.Run()
	stop()
	os.Exit(code)
}

func testKey(t *testing.T) (*signing.Key, openpgp.EntityList) {
	t.Helper()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.asc")

	entity, err := openpgp.NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(privPath)
	if err != nil {
		t.Fatal(err)
	}
	w, err := armor.Encode(f, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	_ = f.Close()

	key, err := signing.Load(privPath)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := key.PublicKeyring()
	if err != nil {
		t.Fatal(err)
	}
	return key, keyring
}

// buildFakeUpstream returns the URL of an httptest server serving a minimal
// signed repo for suite "trixie", component "main", arch "amd64", tagged
// Cache-Control: no-cache so its Valkey-published copy is *never* considered
// fresh by the normal Expires-based adopt path -- the only way a Build call
// can avoid a real request is the layout-freshness mechanism under test,
// with no timing-window confound from the ordinary freshness check. calls
// counts every request the server receives, so tests can prove whether a
// Build call touched the network at all.
func buildFakeUpstream(t *testing.T, key *signing.Key) (srvURL string, calls *atomic.Int32) {
	t.Helper()
	calls = &atomic.Int32{}

	packagesContent := []byte("Package: hello\nVersion: 1.0\nArchitecture: amd64\n")
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(packagesContent); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	gzSum := sha256.Sum256(gzBuf.Bytes())

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n",
		hex.EncodeToString(gzSum[:]), gzBuf.Len(),
	))
	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, calls
}

// buildFakeUpstreamWithBreakableSources is buildFakeUpstream plus a Sources
// endpoint whose failure can be toggled on demand, for testing what happens
// when one data kind (Sources) keeps failing while the other (Index) keeps
// succeeding for the same upstream.
func buildFakeUpstreamWithBreakableSources(t *testing.T, key *signing.Key) (srvURL string, indexCalls *atomic.Int32, breakSources *atomic.Bool) {
	t.Helper()
	indexCalls = &atomic.Int32{}
	breakSources = &atomic.Bool{}

	packagesContent := []byte("Package: hello\nVersion: 1.0\nArchitecture: amd64\n")
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(packagesContent); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	gzSum := sha256.Sum256(gzBuf.Bytes())

	sourcesContent := []byte("Package: hello\nVersion: 1.0\nDirectory: pool/main/h/hello\n")
	sourcesSum := sha256.Sum256(sourcesContent)

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n %s %d main/source/Sources\n",
		hex.EncodeToString(gzSum[:]), gzBuf.Len(),
		hex.EncodeToString(sourcesSum[:]), len(sourcesContent),
	))
	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		indexCalls.Add(1)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		indexCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	})
	mux.HandleFunc("/dists/trixie/main/source/Sources", func(w http.ResponseWriter, r *http.Request) {
		if breakSources.Load() {
			// A genuine transport failure, not a status code -- a bad status
			// for one variant is treated as "try the next variant", not a
			// hard failure (matches internal/upstream's own fetchSourcesFile
			// test for this exact distinction).
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
				}
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sourcesContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, indexCalls, breakSources
}

func testConfigWithSources(srvURL string, keyring openpgp.EntityList) *config.Config {
	src := model.UpstreamSource{
		Name:         "test-upstream",
		URL:          srvURL,
		Suite:        "trixie",
		Component:    "main",
		Archs:        []string{"amd64"},
		VerifyKeys:   keyring,
		FetchSources: true,
	}
	return &config.Config{
		Schedule: config.ScheduleConfig{Refresh: "1h"},
		ResolvedLayouts: []model.Layout{
			{OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"}, Upstreams: []model.UpstreamSource{src}},
		},
	}
}

func testConfig(srvURL string, keyring openpgp.EntityList) *config.Config {
	src := model.UpstreamSource{
		Name:       "test-upstream",
		URL:        srvURL,
		Suite:      "trixie",
		Component:  "main",
		Archs:      []string{"amd64"},
		VerifyKeys: keyring,
	}
	return &config.Config{
		// A real, positive schedule.refresh is required for
		// MarkLayoutDataFresh to persist anything at all (ttl <= 0 is a
		// deliberate no-op -- see its own doc comment).
		Schedule: config.ScheduleConfig{Refresh: "1h"},
		ResolvedLayouts: []model.Layout{
			{OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"}, Upstreams: []model.UpstreamSource{src}},
		},
	}
}

func newRawTestClient(t *testing.T) valkey.Client {
	t.Helper()
	client, err := testsupport.NewClient(testValkeyAddr)
	if err != nil {
		t.Fatalf("connecting to test valkey: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Do(context.Background(), client.B().Flushdb().Build()).Error()
		client.Close()
	})
	return client
}

// TestBuildEstablishesLayoutFreshnessAfterRealFetch proves the fix for the
// original production symptom: a layout's freshness marker (see
// upstream.IndexCache.MarkLayoutDataFresh) is established by *any* Build
// call's own successful real fetch, not only by the periodic refresher's own
// cycle -- which can otherwise be delayed by up to a full schedule.refresh
// interval on a fresh deploy (see layoutSeedOffset in cmd/debproxy). The
// upstream sends Cache-Control: no-cache, so the ordinary Expires-based
// adopt path never applies here -- the only way a Build call can avoid a
// real request is the layout-freshness mechanism under test.
func TestBuildEstablishesLayoutFreshnessAfterRealFetch(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, calls := buildFakeUpstream(t, key)
	cfg := testConfig(srvURL, keyring)

	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-avail-fresh:"}
	ctx := context.Background()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)

	// First Build: nothing cached anywhere yet, so this must really fetch --
	// and, on success, establish the layout as freshly synced on its own.
	av1 := avail.Build(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	if len(av1.Pkgs["main"]["amd64"]) == 0 {
		t.Fatal("expected packages after the first Build")
	}
	callsAfterFirst := calls.Load()
	if callsAfterFirst == 0 {
		t.Fatal("expected at least one real request on the first Build")
	}

	// Second Build, immediately after, no external seeding at all: since
	// no-cache means the ordinary Expires-based adopt path never applies,
	// zero additional requests here can only mean the first Build's own
	// success already established this layout as fresh.
	av2 := avail.Build(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	if calls.Load() != callsAfterFirst {
		t.Fatalf("expected no additional requests once a prior Build call established freshness, got %d more",
			calls.Load()-callsAfterFirst)
	}
	if av2.Pkgs["main"]["amd64"]["hello"].Version != av1.Pkgs["main"]["amd64"]["hello"].Version {
		t.Fatalf("adopted package data mismatch: got %+v want %+v",
			av2.Pkgs["main"]["amd64"]["hello"], av1.Pkgs["main"]["amd64"]["hello"])
	}
}

// TestBuildTrustsAnotherReplicasLayoutFreshness proves the freshness marker
// is genuinely shared across replicas: a brand new IndexCache (standing in
// for a different debproxy process) that has never fetched anything itself
// still adopts outright, purely because another cache instance already
// established the layout as fresh in the same Valkey deployment.
func TestBuildTrustsAnotherReplicasLayoutFreshness(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, calls := buildFakeUpstream(t, key)
	cfg := testConfig(srvURL, keyring)

	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-avail-fresh-shared:"}
	ctx := context.Background()

	cache1 := upstream.NewIndexCache()
	cache1.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	av1 := avail.Build(ctx, cfg, http.DefaultClient, cache1, "debian", "trixie")
	if len(av1.Pkgs["main"]["amd64"]) == 0 {
		t.Fatal("expected packages after the first replica's Build")
	}
	callsAfterFirst := calls.Load()
	if callsAfterFirst == 0 {
		t.Fatal("expected at least one real request on the first replica's Build")
	}

	// A second, independent replica: brand new local state, same Valkey.
	cache2 := upstream.NewIndexCache()
	cache2.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	av2 := avail.Build(ctx, cfg, http.DefaultClient, cache2, "debian", "trixie")
	if calls.Load() != callsAfterFirst {
		t.Fatalf("expected the second replica to adopt outright with no additional requests, got %d more",
			calls.Load()-callsAfterFirst)
	}
	if av2.Pkgs["main"]["amd64"]["hello"].Version != av1.Pkgs["main"]["amd64"]["hello"].Version {
		t.Fatalf("adopted package data mismatch: got %+v want %+v",
			av2.Pkgs["main"]["amd64"]["hello"], av1.Pkgs["main"]["amd64"]["hello"])
	}
}

// TestBuildDoesNotMarkFreshWhenSourcesFetchFails proves a real bug found in
// review: a layout must not be marked fresh just because its Index fetch
// succeeded if that same call's Sources fetch failed -- otherwise the next
// Build call would adopt the Sources side outright too, permanently masking
// a broken Sources upstream behind its sibling's success (since every future
// call would keep re-marking the layout fresh without ever giving the
// broken Sources fetch another real attempt).
func TestBuildDoesNotMarkFreshWhenSourcesFetchFails(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, indexCalls, breakSources := buildFakeUpstreamWithBreakableSources(t, key)
	cfg := testConfigWithSources(srvURL, keyring)

	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-avail-partial-fail:"}
	ctx := context.Background()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)

	// First Build: Index succeeds, but Sources is broken for this call.
	breakSources.Store(true)
	av1 := avail.Build(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	if len(av1.Pkgs["main"]["amd64"]) == 0 {
		t.Fatal("expected Index packages despite Sources failing")
	}
	if len(av1.Srcs["main"]) != 0 {
		t.Fatal("expected no Sources entries while Sources is broken")
	}
	indexCallsAfterFirst := indexCalls.Load()
	if indexCallsAfterFirst == 0 {
		t.Fatal("expected at least one real Index request on the first Build")
	}

	// Second Build, Sources now fixed: if the layout was incorrectly marked
	// fresh despite the first call's Sources failure, Index would now adopt
	// outright (no new request) instead of fetching for real again.
	breakSources.Store(false)
	av2 := avail.Build(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	if indexCalls.Load() == indexCallsAfterFirst {
		t.Fatal("expected a real Index request on the second Build -- the layout must not have been marked fresh after the first call's Sources failure")
	}
	if len(av2.Srcs["main"]) == 0 {
		t.Fatal("expected Sources entries now that Sources is fixed")
	}
}

// TestResolvePoolPathFindsPackageDirectlyFromUpstream is the direct
// regression test for the live-path fallback this session's ubuntu-security
// incident motivated: ResolvePoolPath must find a real, available package by
// checking just the one upstream its pool path names, entirely independent
// of whether any layout-wide Available view (av.ByPoolPath) has ever been
// built at all -- it's called only after that lookup already missed.
func TestResolvePoolPathFindsPackageDirectlyFromUpstream(t *testing.T) {
	key, keyring := testKey(t)

	control, err := apt.ParseStanza("Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\n")
	if err != nil {
		t.Fatal(err)
	}
	deb := []byte("fake deb content")
	sum := sha256.Sum256(deb)
	const upstreamFilename = "pool/main/h/hello/hello_1.0_amd64.deb"
	stanza := apt.BuildPackagesStanza(control, upstreamFilename, int64(len(deb)), hex.EncodeToString(sum[:]), "")
	stanzaStr, err := apt.StanzaString(stanza)
	if err != nil {
		t.Fatal(err)
	}
	packagesContent := []byte(stanzaStr)

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(packagesContent); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	gzSum := sha256.Sum256(gzBuf.Bytes())

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n",
		hex.EncodeToString(gzSum[:]), gzBuf.Len(),
	))
	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := testConfig(srv.URL, keyring) // upstream Name: "test-upstream"
	poolPath := model.PoolPath("debian", "trixie", "test-upstream", "utils", "hello", "1.0", "amd64")

	p, err := avail.ResolvePoolPath(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie", poolPath)
	if err != nil {
		t.Fatalf("ResolvePoolPath: %v", err)
	}
	if p.Name != "hello" || p.Version != "1.0" {
		t.Fatalf("resolved wrong package: %+v", p)
	}
	if p.PoolPath != poolPath {
		t.Fatalf("resolved PoolPath = %q, want %q", p.PoolPath, poolPath)
	}
}

// TestResolvePoolPathUnknownUpstreamFails is the bad-data counterpart: a pool
// path naming an upstream not configured for this os/codename at all must
// fail cleanly, not panic or silently match something else.
func TestResolvePoolPathUnknownUpstreamFails(t *testing.T) {
	_, keyring := testKey(t)
	cfg := testConfig("http://127.0.0.1:1", keyring) // upstream Name: "test-upstream"

	poolPath := model.PoolPath("debian", "trixie", "no-such-upstream", "utils", "hello", "1.0", "amd64")
	if _, err := avail.ResolvePoolPath(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie", poolPath); err == nil {
		t.Fatal("expected an error for a pool path naming an unconfigured upstream")
	}
}

// TestResolvePoolPathWrongVersionFails proves ResolvePoolPath doesn't just
// match on package name -- a pool path for a version the upstream doesn't
// currently have (even though the same-named package does exist) must fail.
func TestResolvePoolPathWrongVersionFails(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _ := buildFakeUpstream(t, key) // serves hello 1.0 only
	cfg := testConfig(srvURL, keyring)

	poolPath := model.PoolPath("debian", "trixie", "test-upstream", "", "hello", "9.9", "amd64")
	if _, err := avail.ResolvePoolPath(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie", poolPath); err == nil {
		t.Fatal("expected an error for a pool path naming a version the upstream doesn't have")
	}
}

// TestQuickFingerprintFailsOnColdCache proves QuickFingerprint reports
// ok=false rather than fabricating a fingerprint when it has no basis for
// comparison at all (nothing cached locally, no Valkey) -- the caller must
// fall back to a real Build in that case, never treat a cold cache as
// "confirmed unchanged."
func TestQuickFingerprintFailsOnColdCache(t *testing.T) {
	_, keyring := testKey(t)
	cfg := testConfig("http://127.0.0.1:1", keyring)

	_, ok := avail.QuickFingerprint(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie")
	if ok {
		t.Fatal("expected ok=false with nothing cached anywhere")
	}
}

// TestQuickFingerprintStableAndNetworkFreeAfterWarm is the direct
// regression test for the point of QuickFingerprint existing at all: once
// warmed by one real Build, repeated calls must be network-free (no
// additional InRelease/Packages requests at all -- see ReleaseOnly, which
// only ever reads the local cache or a single lightweight Valkey key, never
// re-fetching real content) and must return the identical fingerprint every
// time the underlying data hasn't changed.
func TestQuickFingerprintStableAndNetworkFreeAfterWarm(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, calls := buildFakeUpstream(t, key)
	cfg := testConfig(srvURL, keyring)
	cache := upstream.NewIndexCache()
	ctx := context.Background()

	avail.Build(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	callsAfterWarm := calls.Load()
	if callsAfterWarm == 0 {
		t.Fatal("expected the warming Build to have made at least one real request")
	}

	fp1, ok := avail.QuickFingerprint(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	if !ok {
		t.Fatal("expected ok=true once the local cache is warm")
	}
	if calls.Load() != callsAfterWarm {
		t.Fatalf("QuickFingerprint made %d additional network request(s), want 0", calls.Load()-callsAfterWarm)
	}

	fp2, ok := avail.QuickFingerprint(ctx, cfg, http.DefaultClient, cache, "debian", "trixie")
	if !ok {
		t.Fatal("expected ok=true on the second call")
	}
	if fp1 != fp2 {
		t.Fatal("expected the same fingerprint from two calls against unchanged data")
	}
	if calls.Load() != callsAfterWarm {
		t.Fatalf("second QuickFingerprint call made %d additional network request(s), want 0", calls.Load()-callsAfterWarm)
	}
}

// TestQuickFingerprintChangesWhenPackagesChange proves the fingerprint
// actually tracks real content: warming against one Packages version, then
// against a genuinely different one (a real, fresh fetch each time -- no
// shared cache between the two Builds, so this isolates "does the digest
// reflect the upstream's Release" from any caching behavior) must produce
// two different fingerprints.
func TestQuickFingerprintChangesWhenPackagesChange(t *testing.T) {
	key, keyring := testKey(t)
	ctx := context.Background()

	srvURL1, _ := buildFakeUpstream(t, key) // hello 1.0
	cfg1 := testConfig(srvURL1, keyring)
	cache1 := upstream.NewIndexCache()
	avail.Build(ctx, cfg1, http.DefaultClient, cache1, "debian", "trixie")
	fp1, ok := avail.QuickFingerprint(ctx, cfg1, http.DefaultClient, cache1, "debian", "trixie")
	if !ok {
		t.Fatal("expected ok=true for the first upstream")
	}

	srvURL2, _, _ := buildFakeUpstreamWithBreakableSources(t, key) // hello 1.0 too, but a distinct Release (different signed bytes/InRelease digest even with identical Package content, since it's a separately-generated server) -- see below for why that alone is enough
	cfg2 := testConfig(srvURL2, keyring)
	cache2 := upstream.NewIndexCache()
	avail.Build(ctx, cfg2, http.DefaultClient, cache2, "debian", "trixie")
	fp2, ok := avail.QuickFingerprint(ctx, cfg2, http.DefaultClient, cache2, "debian", "trixie")
	if !ok {
		t.Fatal("expected ok=true for the second upstream")
	}

	if fp1 == fp2 {
		t.Fatal("expected different fingerprints for two upstreams with different Release file listings (one lists a Sources file, one doesn't)")
	}
}

// TestBuildSetsHasFetchFailureWhenUpstreamUnreachable is the direct
// regression test for the production symptom "an update ran, no new
// packages were found, but packages went missing" one layer up from the
// archsComplete fix: a *total* FetchIndex failure (upstream unreachable, no
// stale fallback cached at all -- not one arch out of several) must be
// surfaced on the returned Available so a caller about to publish it (see
// Server.rebuildLive) can tell "this build is missing a whole upstream"
// apart from "this build is complete." Before HasFetchFailure existed,
// nothing distinguished the two -- Build just silently returned an
// Available with that upstream absent and no signal anywhere on it.
func TestBuildSetsHasFetchFailureWhenUpstreamUnreachable(t *testing.T) {
	_, keyring := testKey(t)
	// Nothing listens here -- guaranteed connection failure -- and cache is
	// freshly created below, so there is no stale fallback of any kind.
	cfg := testConfig("http://127.0.0.1:1", keyring)

	av := avail.Build(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie")
	if !av.HasFetchFailure {
		t.Fatal("expected HasFetchFailure=true when the only configured upstream is unreachable with no stale fallback")
	}
	if len(av.ByPoolPath) != 0 {
		t.Fatalf("expected no packages at all from a fully-failed upstream, got %+v", av.ByPoolPath)
	}
}

// buildFakeUpstreamWithSection is like buildFakeUpstream but sets an
// explicit Section: utils on the one package it serves ("hello" 1.0) --
// needed whenever a test computes the expected pool path via
// model.PoolPath, which (unlike the unexported poolPathFromFilename actually
// used to build it) defaults an empty section to "misc" rather than leaving
// it blank, so the two would otherwise disagree for a section-less stanza.
func buildFakeUpstreamWithSection(t *testing.T, key *signing.Key) (srvURL string) {
	t.Helper()

	control, err := apt.ParseStanza("Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\n")
	if err != nil {
		t.Fatal(err)
	}
	deb := []byte("fake deb content")
	sum := sha256.Sum256(deb)
	const upstreamFilename = "pool/main/h/hello/hello_1.0_amd64.deb"
	stanza := apt.BuildPackagesStanza(control, upstreamFilename, int64(len(deb)), hex.EncodeToString(sum[:]), "")
	stanzaStr, err := apt.StanzaString(stanza)
	if err != nil {
		t.Fatal(err)
	}
	packagesContent := []byte(stanzaStr)

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(packagesContent); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	gzSum := sha256.Sum256(gzBuf.Bytes())

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n",
		hex.EncodeToString(gzSum[:]), gzBuf.Len(),
	))
	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// buildFakeSourceUpstream serves a signed repo with an empty binary index
// (no packages -- irrelevant to this test) and a single Sources stanza for
// "hello" at the given version.
func buildFakeSourceUpstream(t *testing.T, key *signing.Key, version string) (srvURL string) {
	t.Helper()

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	gzSum := sha256.Sum256(gzBuf.Bytes())

	sourcesContent := []byte(fmt.Sprintf("Package: hello\nVersion: %s\nDirectory: pool/main/h/hello\n", version))
	sourcesSum := sha256.Sum256(sourcesContent)

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n %s %d main/source/Sources\n",
		hex.EncodeToString(gzSum[:]), gzBuf.Len(),
		hex.EncodeToString(sourcesSum[:]), len(sourcesContent),
	))
	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	})
	mux.HandleFunc("/dists/trixie/main/source/Sources", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sourcesContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestBuildPicksHigherSourceVersionByDebianOrderingNotLexicographic is the
// regression test for a second, distinct bug found alongside the ByPoolPath
// merge-ambiguity issue: the Srcs merge compared versions with
// strings.Compare (plain lexicographic ordering) instead of
// debversion.Compare (real Debian version ordering). "10" sorts before "9"
// lexicographically but must rank higher under Debian version rules -- with
// the bug, an upstream offering the genuinely newer "10" would lose to an
// upstream offering "9", exactly backwards, with no error anywhere to
// suggest anything went wrong.
func TestBuildPicksHigherSourceVersionByDebianOrderingNotLexicographic(t *testing.T) {
	key, keyring := testKey(t)
	srvOld := buildFakeSourceUpstream(t, key, "9")
	srvNew := buildFakeSourceUpstream(t, key, "10")

	cfg := &config.Config{
		ResolvedLayouts: []model.Layout{{
			OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"},
			Upstreams: []model.UpstreamSource{
				{Name: "upstream-old", URL: srvOld, Suite: "trixie", Component: "main", Archs: []string{"amd64"}, VerifyKeys: keyring, FetchSources: true},
				{Name: "upstream-new", URL: srvNew, Suite: "trixie", Component: "main", Archs: []string{"amd64"}, VerifyKeys: keyring, FetchSources: true},
			},
		}},
	}

	av := avail.Build(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie")
	got, ok := av.Srcs["main"]["hello"]
	if !ok {
		t.Fatal("expected a merged Srcs entry for hello")
	}
	if got.Version != "10" {
		t.Fatalf("expected version 10 (the real latest under Debian ordering) to win, got %q", got.Version)
	}
}

// TestBuildKeepsBothPoolPathsWhenTwoUpstreamsShareAVersion is the direct
// regression test for a real, previously unexamined cause of "package not
// in current live index" that has nothing to do with any fetch failure:
// two upstreams commonly carry the exact identical version of the same
// package at once (e.g. Ubuntu routinely publishes a security fix to both
// -security and -updates), and Phase 2a/2b's merge only ever recorded
// ByPoolPath for whichever upstream's entry happened to win the
// name -> Pkg "canonical" slot -- decided by which of several concurrent
// goroutines finished first, not by anything deterministic. The loser's
// pool path -- exactly as real and fetchable as the winner's -- vanished
// from ByPoolPath entirely. A client whose own previously-served Packages
// listing named that exact upstream then found nothing at that path on
// this rebuild, needing the live-path fallback every time, with no error
// or incompleteness anywhere in the fetch itself. Run with -count and race
// detection in mind: the whole point is this must hold regardless of which
// upstream's goroutine happens to finish first.
func TestBuildKeepsBothPoolPathsWhenTwoUpstreamsShareAVersion(t *testing.T) {
	key, keyring := testKey(t)
	srvA := buildFakeUpstreamWithSection(t, key) // serves "hello" 1.0, Section: utils
	srvB := buildFakeUpstreamWithSection(t, key) // an independent server, same signed content

	cfg := &config.Config{
		ResolvedLayouts: []model.Layout{{
			OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"},
			Upstreams: []model.UpstreamSource{
				{Name: "upstream-a", URL: srvA, Suite: "trixie", Component: "main", Archs: []string{"amd64"}, VerifyKeys: keyring},
				{Name: "upstream-b", URL: srvB, Suite: "trixie", Component: "main", Archs: []string{"amd64"}, VerifyKeys: keyring},
			},
		}},
	}

	poolPathA := model.PoolPath("debian", "trixie", "upstream-a", "utils", "hello", "1.0", "amd64")
	poolPathB := model.PoolPath("debian", "trixie", "upstream-b", "utils", "hello", "1.0", "amd64")

	// Run several times: the "winner" of the canonical Pkgs slot is decided
	// by goroutine completion order, which varies run to run. Both pool
	// paths must survive every single time regardless of which one wins.
	for i := 0; i < 10; i++ {
		av := avail.Build(context.Background(), cfg, http.DefaultClient, upstream.NewIndexCache(), "debian", "trixie")
		if _, ok := av.ByPoolPath[poolPathA]; !ok {
			t.Fatalf("run %d: upstream-a's pool path missing from ByPoolPath", i)
		}
		if _, ok := av.ByPoolPath[poolPathB]; !ok {
			t.Fatalf("run %d: upstream-b's pool path missing from ByPoolPath", i)
		}
		// The served Packages listing must still show exactly one canonical
		// entry per name -- this fix must not cause duplicates there.
		if _, ok := av.Pkgs["main"]["amd64"]["hello"]; !ok {
			t.Fatalf("run %d: expected exactly one canonical entry in Pkgs", i)
		}
	}
}

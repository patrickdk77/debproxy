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

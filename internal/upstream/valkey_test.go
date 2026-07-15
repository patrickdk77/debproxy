package upstream_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/testsupport"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// TestMain starts one real Valkey container for the whole test binary run
// (see testsupport.StartValkey for why a real server rather than a mock --
// these tests in particular rely on real lock/expiry semantics).
func TestMain(m *testing.M) {
	testsupport.RunMain(m, &upstream.TestValkeyAddr)
}

// newRawTestClient returns a fresh Valkey client connected to the shared test
// container, and registers a cleanup that flushes the database and closes
// the connection.
func newRawTestClient(t *testing.T) valkey.Client {
	return testsupport.NewTestClient(t, upstream.TestValkeyAddr)
}

// countingProxy wraps srvURL in an httptest.Server that forwards every
// request verbatim, counts requests, and stamps the given Cache-Control
// header on the response so tests can control freshness precisely.
func countingProxy(t *testing.T, srvURL, cacheControl string) (proxyURL string, calls *atomic.Int32) {
	t.Helper()
	calls = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		resp, err := http.Get(srvURL + r.RequestURI)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.WriteHeader(resp.StatusCode)
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err == nil {
			_, _ = w.Write(buf.Bytes())
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, calls
}

func TestFetchIndexAdoptsFromValkeySkipsNetworkOnOtherReplica(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	proxyURL, calls := countingProxy(t, srvURL, "max-age=3600")

	src := makeSource(t, proxyURL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-adopt:"}
	ctx := context.Background()

	cache1 := upstream.NewIndexCache()
	cache1.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f1 := upstream.NewFetcherWithCache(src, nil, cache1)

	idx1, err := f1.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := calls.Load()
	if callsAfterFirst == 0 {
		t.Fatal("expected at least one network call for the first replica's fetch")
	}

	// Simulate a second, independent replica process: a brand new IndexCache
	// with no local state at all, sharing only the same Valkey backend.
	cache2 := upstream.NewIndexCache()
	cache2.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f2 := upstream.NewFetcherWithCache(src, nil, cache2)

	idx2, err := f2.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != callsAfterFirst {
		t.Fatalf("expected the second replica to adopt from valkey without hitting the network, but %d more calls were made",
			calls.Load()-callsAfterFirst)
	}
	if len(idx2.ByArch["amd64"]) == 0 || idx2.ByArch["amd64"][0].Package != "hello" {
		t.Fatalf("adopted index content mismatch: %+v", idx2)
	}
	if len(idx1.ByArch["amd64"]) != len(idx2.ByArch["amd64"]) {
		t.Fatalf("adopted index has different package count: got %d want %d",
			len(idx2.ByArch["amd64"]), len(idx1.ByArch["amd64"]))
	}
}

func TestFetchIndexLockContentionServesLocalStaleInsteadOfDuplicateFetch(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	// A short max-age so both the local and Valkey copies genuinely expire
	// within the test, rather than relying on the 5-minute fallback default.
	proxyURL, calls := countingProxy(t, srvURL, "max-age=1")

	src := makeSource(t, proxyURL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-lockcontention:"}
	ctx := context.Background()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f := upstream.NewFetcherWithCache(src, nil, cache)

	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := calls.Load()
	if callsAfterFirst == 0 {
		t.Fatal("expected at least one network call after first fetch")
	}

	// Wait past the 1s freshness window so both local and valkey copies are stale.
	time.Sleep(1200 * time.Millisecond)

	// Simulate another replica holding the fetch lock right now.
	lockKey := keys.FetchLock(src.Name, src.Suite, src.Component)
	lock, ok, err := valkeycache.AcquireLock(ctx, rawClient, lockKey, time.Minute)
	if err != nil || !ok {
		t.Fatalf("pre-acquire lock: ok=%v err=%v", ok, err)
	}
	defer lock.Release(ctx)

	// This replica still has its own (now-stale) local copy from the first
	// fetch, so it should serve that instead of duplicating the network
	// request while another replica holds the lock.
	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != callsAfterFirst {
		t.Fatalf("expected no new network calls while lock is held elsewhere, got %d more calls",
			calls.Load()-callsAfterFirst)
	}
}

func TestFetchIndexReleasesLockAfterFetch(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	proxyURL, _ := countingProxy(t, srvURL, "max-age=3600")

	src := makeSource(t, proxyURL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-lockrelease:"}
	ctx := context.Background()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f := upstream.NewFetcherWithCache(src, nil, cache)

	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}

	// The lock must be released once the fetch completes -- a fresh
	// acquisition attempt right after must succeed.
	lockKey := keys.FetchLock(src.Name, src.Suite, src.Component)
	lock, ok, err := valkeycache.AcquireLock(ctx, rawClient, lockKey, time.Minute)
	if err != nil {
		t.Fatalf("acquire after fetch: %v", err)
	}
	if !ok {
		t.Fatal("expected fetch lock to be released after FetchIndex completed")
	}
	_ = lock.Release(ctx)
}

// TestFetchIndexAfterEvictionReusesViaValkeyComparison proves the core claim
// behind IndexCache.EvictUpstream: evicting a layout's local cache entry
// after a refresh cycle (as refreshLayoutGroup now does) doesn't force a full
// re-download on the next cycle. The fetcher falls back to Valkey's
// last-published copy (regardless of freshness) as its conditional-GET/reuse
// comparison basis instead, so an unchanged upstream still gets a cheap 304
// and reused Packages data rather than a full redownload.
func TestFetchIndexAfterEvictionReusesViaValkeyComparison(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)

	var inReleaseCalls, packagesCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/trixie/InRelease":
			inReleaseCalls.Add(1)
			if r.Header.Get("If-None-Match") == `"test-etag-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			// no-cache forces conditional revalidation on every fetch instead of
			// serving from the fresh-expiry fast path, same as TestFetchIndex304ReusesCache.
			w.Header().Set("ETag", `"test-etag-1"`)
			w.Header().Set("Cache-Control", "no-cache")
		case "/dists/trixie/main/binary-amd64/Packages.gz":
			packagesCalls.Add(1)
		}
		resp, err := http.Get(srvURL + r.RequestURI)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	src := makeSource(t, srv.URL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-evict:"}
	ctx := context.Background()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f := upstream.NewFetcherWithCache(src, nil, cache)

	idx1, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx1.ByArch["amd64"]) == 0 {
		t.Fatal("expected packages after first fetch")
	}
	packagesCallsAfterFirst := packagesCalls.Load()
	if packagesCallsAfterFirst == 0 {
		t.Fatal("expected at least one Packages.gz download on first fetch")
	}

	// Simulate refreshLayoutGroup's post-cycle eviction (cmd/debproxy/main.go):
	// the local cache no longer has anything for this upstream, only Valkey does.
	cache.EvictUpstream(f.InReleaseURL(), f.Component())

	idx2, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inReleaseCalls.Load() < 2 {
		t.Fatalf("expected at least 2 InRelease requests (initial + post-eviction conditional), got %d", inReleaseCalls.Load())
	}
	if packagesCalls.Load() != packagesCallsAfterFirst {
		t.Fatalf("expected no additional Packages.gz downloads after eviction (should reuse via Valkey comparison), got %d more",
			packagesCalls.Load()-packagesCallsAfterFirst)
	}
	if len(idx2.ByArch["amd64"]) != len(idx1.ByArch["amd64"]) {
		t.Fatal("post-eviction index disagrees with pre-eviction index on package count")
	}
}

// buildFakeUpstreamWithSources is buildFakeUpstream plus a minimal signed
// Sources index, since buildFakeUpstream's repo has no source packages at
// all (nothing for FetchSources to find or cache).
func buildFakeUpstreamWithSources(t *testing.T, key *signing.Key) (srvURL string) {
	t.Helper()

	sourcesContent := []byte("Package: hello\nVersion: 1.0\nDirectory: pool/main/h/hello\n")
	sourcesSum := sha256.Sum256(sourcesContent)

	packagesContent := []byte("Package: hello\nVersion: 1.0\nArchitecture: amd64\n")
	packagesSum := sha256.Sum256(packagesContent)

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages\n %s %d main/source/Sources\n",
		hex.EncodeToString(packagesSum[:]), len(packagesContent),
		hex.EncodeToString(sourcesSum[:]), len(sourcesContent),
	))
	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packagesContent)
	})
	mux.HandleFunc("/dists/trixie/main/source/Sources", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sourcesContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFetchSourcesAdoptsFromValkeySkipsNetworkOnOtherReplica(t *testing.T) {
	key, keyring := testKey(t)
	srvURL := buildFakeUpstreamWithSources(t, key)
	proxyURL, calls := countingProxy(t, srvURL, "max-age=3600")

	src := makeSource(t, proxyURL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-adopt-srcs:"}
	ctx := context.Background()

	// FetchIndex must run first (in this codebase's design, srcs freshness
	// is gated by the same meta/Expires that only FetchIndex populates --
	// see IndexCache.updateSrcs, which never sets an entry's expires on its
	// own even when creating a brand new entry).
	cache1 := upstream.NewIndexCache()
	cache1.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f1 := upstream.NewFetcherWithCache(src, nil, cache1)
	if _, err := f1.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srcs, err := f1.FetchSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) == 0 || srcs[0].Package != "hello" {
		t.Fatalf("expected hello source entry, got %+v", srcs)
	}
	callsAfterFirstReplica := calls.Load()

	cache2 := upstream.NewIndexCache()
	cache2.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	f2 := upstream.NewFetcherWithCache(src, nil, cache2)
	if _, err := f2.FetchSources(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != callsAfterFirstReplica {
		t.Fatalf("expected no new network calls for the second replica's FetchSources, got %d more",
			calls.Load()-callsAfterFirstReplica)
	}
}

// TestAdoptSourcesFromValkeyOutrightAfterIndexAdoptedFirst reproduces
// avail.Build's own sequencing on a single shared IndexCache: every
// upstream's Index is adopted first (AdoptFromValkeyOutright), populating
// the local cache entry with only Index fields via IndexCache.store, before
// any upstream's Sources is adopted (AdoptSourcesFromValkeyOutright) --
// sharing that same entry (both are keyed by upstream+suite+component only).
// A fresh entry with no prior Sources data has nothing for store's merge to
// carry over, so the local entry Sources adoption sees really does have nil
// srcs -- cachedForComparison/srcsCachedForComparison must not treat that as
// "nothing available anywhere" and skip checking Valkey, which is exactly
// what happened before the fix: Sources adoption always missed and fell
// through to a real network fetch, on every single call, for every upstream,
// solely because its own Index had just been adopted moments earlier.
func TestAdoptSourcesFromValkeyOutrightAfterIndexAdoptedFirst(t *testing.T) {
	key, keyring := testKey(t)
	srvURL := buildFakeUpstreamWithSources(t, key)
	proxyURL, calls := countingProxy(t, srvURL, "max-age=3600")

	src := makeSource(t, proxyURL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-adopt-idx-then-srcs:"}
	ctx := context.Background()

	// Seed Valkey with real Index and Sources data via one genuine fetch.
	seedCache := upstream.NewIndexCache()
	seedCache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	seedFetcher := upstream.NewFetcherWithCache(src, nil, seedCache)
	if _, err := seedFetcher.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := seedFetcher.FetchSources(ctx); err != nil {
		t.Fatal(err)
	}
	callsAfterSeed := calls.Load()

	// A fresh cache/process (e.g. a cold-start /live request) adopts Index
	// outright first, exactly as avail.Build's Index loop does before its
	// Sources loop ever starts.
	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	indexFetcher := upstream.NewFetcherWithCache(src, nil, cache)
	if _, ok := indexFetcher.AdoptFromValkeyOutright(ctx); !ok {
		t.Fatal("expected Index to adopt from valkey outright")
	}

	// Sources adoption for the same upstream, sharing the same cache, must
	// still find Valkey's real Sources data -- not be short-circuited by the
	// Index-only entry the line above just stored locally.
	srcsFetcher := upstream.NewFetcherWithCache(src, nil, cache)
	srcs, ok := srcsFetcher.AdoptSourcesFromValkeyOutright(ctx)
	if !ok {
		t.Fatal("expected Sources to adopt from valkey outright after Index already populated the shared local cache entry")
	}
	if len(srcs) == 0 || srcs[0].Package != "hello" {
		t.Fatalf("expected hello source entry, got %+v", srcs)
	}
	if calls.Load() != callsAfterSeed {
		t.Fatalf("expected no additional upstream network calls, got %d more", calls.Load()-callsAfterSeed)
	}
}

// TestAdoptFromValkeyOutrightTrustsConfirmedEmptyArchs covers an upstream
// configured for an architecture its Release never lists a Packages file
// for (e.g. a mirror that only serves amd64, configured with arm64) --
// releaseServedArchs confirms this from the cached Release alone, so
// AdoptFromValkeyOutright must trust an empty ByArch as the correct,
// already-resolved answer instead of treating it as "not yet cached" and
// falling through to a real, pointless re-fetch that will find the exact
// same nothing every time.
func TestAdoptFromValkeyOutrightTrustsConfirmedEmptyArchs(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key) // Release lists only amd64
	proxyURL, calls := countingProxy(t, srvURL, "max-age=3600")

	src := model.UpstreamSource{
		Name:       "test-upstream",
		URL:        proxyURL,
		Suite:      "trixie",
		Component:  "main",
		Archs:      []string{"arm64"}, // Release has no arm64 Packages at all
		VerifyKeys: keyring,
	}
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-adopt-empty-archs:"}
	ctx := context.Background()

	seedCache := upstream.NewIndexCache()
	seedCache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	seedFetcher := upstream.NewFetcherWithCache(src, nil, seedCache)
	idx, err := seedFetcher.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.ByArch) != 0 {
		t.Fatalf("expected no arm64 packages from a Release that only lists amd64, got %+v", idx.ByArch)
	}
	callsAfterSeed := calls.Load()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	fetcher := upstream.NewFetcherWithCache(src, nil, cache)
	adopted, ok := fetcher.AdoptFromValkeyOutright(ctx)
	if !ok {
		t.Fatal("expected outright adoption of a confirmed-empty Release, not a miss")
	}
	if len(adopted.ByArch) != 0 {
		t.Fatalf("expected empty ByArch, got %+v", adopted.ByArch)
	}
	if calls.Load() != callsAfterSeed {
		t.Fatalf("expected no additional upstream network calls, got %d more", calls.Load()-callsAfterSeed)
	}
}

// TestAdoptFromValkeyOutrightRejectsPartiallyUnreadableArchs is the
// regression test for a real production incident: one arch's Valkey bucket
// read failing (a transient error, simulated here by corrupting one stored
// entry so it fails JSON decoding) must not be mistaken for "this upstream
// confirmedly has nothing for that arch" just because a *different*,
// unaffected arch still has data (making the overall ByArch non-empty).
// Before archsComplete existed, AdoptFromValkeyOutright's only guard was
// "ByArch is empty AND the Release claims to serve something" -- which this
// scenario slips past entirely (ByArch has amd64 data, so len != 0), so it
// adopted an index silently missing all of arm64's packages. In production
// this surfaced as many real, available ubuntu-security packages being
// reported "not in current live index" long after any restart/rebuild, with
// no further rebuild ever correcting it.
func TestAdoptFromValkeyOutrightRejectsPartiallyUnreadableArchs(t *testing.T) {
	key, keyring := testKey(t)
	srvURL := buildFakeUpstreamTwoArches(t, key)

	src := model.UpstreamSource{
		Name:       "test-upstream",
		URL:        srvURL,
		Suite:      "trixie",
		Component:  "main",
		Archs:      []string{"amd64", "arm64"},
		VerifyKeys: keyring,
	}
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-adopt-partial-archs:"}
	ctx := context.Background()

	seedCache := upstream.NewIndexCache()
	seedCache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	seedFetcher := upstream.NewFetcherWithCache(src, nil, seedCache)
	idx, err := seedFetcher.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.ByArch["amd64"]) != 1 || len(idx.ByArch["arm64"]) != 1 {
		t.Fatalf("expected one package per arch after seeding, got %+v", idx.ByArch)
	}

	// Corrupt arm64's only cached entry so a future read of it fails to
	// decode -- simulating the transient per-arch Valkey read error
	// fetchArchPkgs warns and swallows, distinct from a genuinely empty
	// bucket (which fetchOneArchPkgs returns as (nil, nil), no error).
	entryKey := keys.UpstreamPkgEntry("test-upstream", "trixie", "main", "arm64", "world", "1.0")
	if err := rawClient.Do(ctx, rawClient.B().Set().Key(entryKey).Value("not valid json").Build()).Error(); err != nil {
		t.Fatal(err)
	}

	// A fresh cache with no local state, same Valkey backing -- simulating a
	// different (or restarted) replica adopting outright.
	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	fetcher := upstream.NewFetcherWithCache(src, nil, cache)
	if _, ok := fetcher.AdoptFromValkeyOutright(ctx); ok {
		t.Fatal("expected AdoptFromValkeyOutright to refuse a partially-unreadable index, not adopt it silently")
	}
}

// buildFakeUpstreamTwoArches serves a Release listing two architectures
// (amd64 with package "hello", arm64 with package "world"), each in its own
// Packages file -- for tests that need one arch's Valkey-cached data to be
// independently corruptible from another's.
func buildFakeUpstreamTwoArches(t *testing.T, key *signing.Key) (srvURL string) {
	t.Helper()

	amd64Content := []byte("Package: hello\nVersion: 1.0\nArchitecture: amd64\n")
	arm64Content := []byte("Package: world\nVersion: 1.0\nArchitecture: arm64\n")
	amd64Sum := sha256.Sum256(amd64Content)
	arm64Sum := sha256.Sum256(arm64Content)

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64 arm64\nSHA256:\n %s %d main/binary-amd64/Packages\n %s %d main/binary-arm64/Packages\n",
		hex.EncodeToString(amd64Sum[:]), len(amd64Content),
		hex.EncodeToString(arm64Sum[:]), len(arm64Content),
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
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(amd64Content)
	})
	mux.HandleFunc("/dists/trixie/main/binary-arm64/Packages", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(arm64Content)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestAdoptSourcesFromValkeyOutrightTrustsConfirmedEmptySources covers a
// binary-only upstream whose Release lists no Sources file at all --
// releaseListsSources confirms this from the cached Release alone, so
// AdoptSourcesFromValkeyOutright must trust nil srcs as the correct,
// already-resolved answer instead of treating it as "not yet cached" and
// falling through to a real, pointless re-fetch every time.
func TestAdoptSourcesFromValkeyOutrightTrustsConfirmedEmptySources(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key) // Release lists no Sources variant
	proxyURL, calls := countingProxy(t, srvURL, "max-age=3600")

	src := makeSource(t, proxyURL, keyring)
	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-adopt-empty-srcs:"}
	ctx := context.Background()

	seedCache := upstream.NewIndexCache()
	seedCache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	seedFetcher := upstream.NewFetcherWithCache(src, nil, seedCache)
	if _, err := seedFetcher.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	srcs, err := seedFetcher.FetchSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if srcs != nil {
		t.Fatalf("expected nil srcs from a Release with no Sources variant, got %+v", srcs)
	}
	callsAfterSeed := calls.Load()

	cache := upstream.NewIndexCache()
	cache.EnableValkey(rawClient, keys, time.Minute, 10*time.Second)
	indexFetcher := upstream.NewFetcherWithCache(src, nil, cache)
	if _, ok := indexFetcher.AdoptFromValkeyOutright(ctx); !ok {
		t.Fatal("expected Index to adopt from valkey outright")
	}

	srcsFetcher := upstream.NewFetcherWithCache(src, nil, cache)
	adopted, ok := srcsFetcher.AdoptSourcesFromValkeyOutright(ctx)
	if !ok {
		t.Fatal("expected outright adoption of a confirmed-empty Sources result, not a miss")
	}
	if adopted != nil {
		t.Fatalf("expected nil srcs, got %+v", adopted)
	}
	if calls.Load() != callsAfterSeed {
		t.Fatalf("expected no additional upstream network calls, got %d more", calls.Load()-callsAfterSeed)
	}
}

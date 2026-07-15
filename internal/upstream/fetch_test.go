package upstream_test

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

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/upstream"
)

// testKey generates an in-memory OpenPGP key pair and returns (privKey, keyring).
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

// buildFakeUpstream returns the URL of an httptest server that serves a minimal
// signed Debian repository for the suite "trixie", component "main", arch "amd64".
// It also returns the plain-text Packages content and the deb bytes it serves.
func buildFakeUpstream(t *testing.T, key *signing.Key) (srvURL string, packagesContent []byte, debContent []byte) {
	t.Helper()

	debContent = []byte("fake .deb binary content for test")
	debSum := sha256.Sum256(debContent)
	debSHA256 := hex.EncodeToString(debSum[:])
	debPath := "pool/main/h/hello/hello_1.0_amd64.deb"

	control := apt.NewParagraph()
	control.Set("Package", "hello")
	control.Set("Version", "1.0")
	control.Set("Architecture", "amd64")
	control.Set("Section", "utils")
	control.Set("Maintainer", "T <t@example.com>")
	control.Set("Description", "hello")
	stanza := apt.BuildPackagesStanza(control, debPath, int64(len(debContent)), debSHA256, "")
	var pkgBuf bytes.Buffer
	if err := apt.WriteParagraphs(&pkgBuf, []*apt.Paragraph{stanza}); err != nil {
		t.Fatal(err)
	}
	packagesContent = pkgBuf.Bytes()

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(packagesContent); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	packagesGZ := gzBuf.Bytes()

	plainSum := sha256.Sum256(packagesContent)
	gzSum := sha256.Sum256(packagesGZ)

	releaseBytes := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages\n %s %d main/binary-amd64/Packages.gz\n",
		hex.EncodeToString(plainSum[:]), len(packagesContent),
		hex.EncodeToString(gzSum[:]), len(packagesGZ),
	))

	inRelease, err := key.SignInline(releaseBytes)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"test-etag-1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packagesGZ)
	})
	mux.HandleFunc("/"+debPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(debContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, packagesContent, debContent
}

func makeSource(t *testing.T, srvURL string, keyring openpgp.EntityList) model.UpstreamSource {
	t.Helper()
	return model.UpstreamSource{
		Name:       "test-upstream",
		URL:        srvURL,
		Suite:      "trixie",
		Component:  "main",
		Archs:      []string{"amd64"},
		VerifyKeys: keyring,
	}
}

func TestFetchIndexBasic(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, packagesContent, _ := buildFakeUpstream(t, key)

	src := makeSource(t, srvURL, keyring)
	f := upstream.NewFetcher(src, nil)

	idx, err := f.FetchIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if idx.Release == nil {
		t.Fatal("expected non-nil Release")
	}
	paras := idx.ByArch["amd64"]
	if len(paras) == 0 {
		t.Fatal("expected at least one package in amd64 Packages")
	}
	if paras[0].Package != "hello" {
		t.Fatalf("expected hello package, got %q", paras[0].Package)
	}
	_ = packagesContent
}

func TestFetchIndexFreshCacheSkipsNetwork(t *testing.T) {
	key, keyring := testKey(t)

	var calls atomic.Int32
	srvURL, _, _ := buildFakeUpstream(t, key)

	// Wrap the built server's URL in a counting proxy.
	countingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// forward to real upstream
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
		// Long max-age so the cache entry is fresh.
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(resp.StatusCode)
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err == nil {
			_, _ = w.Write(buf.Bytes())
		}
	}))
	defer countingSrv.Close()

	src := makeSource(t, countingSrv.URL, keyring)
	cache := upstream.NewIndexCache()
	f := upstream.NewFetcherWithCache(src, nil, cache)
	ctx := context.Background()

	// First fetch populates the cache.
	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	firstCalls := calls.Load()

	// Second fetch: cache is fresh (max-age=3600)  --  must not hit the server.
	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != firstCalls {
		t.Fatalf("expected no new requests on fresh cache hit, but %d more calls were made", calls.Load()-firstCalls)
	}
}

func TestFetchIndex304ReusesCache(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)

	var inReleaseCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dists/trixie/InRelease" {
			inReleaseCalls.Add(1)
			if r.Header.Get("If-None-Match") == `"test-etag-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			// no-cache forces re-validation on next request instead of serving
			// from the fresh-expiry fast path.
			w.Header().Set("ETag", `"test-etag-1"`)
			w.Header().Set("Cache-Control", "no-cache")
		}
		// Proxy all other requests to the real upstream.
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
	cache := upstream.NewIndexCache()
	f := upstream.NewFetcherWithCache(src, nil, cache)
	ctx := context.Background()

	// First fetch: populates cache (InRelease returns ETag).
	idx1, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Second fetch: server returns 304; fetcher should reuse cached Packages.
	idx2, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if inReleaseCalls.Load() < 2 {
		t.Fatalf("expected at least 2 InRelease requests (initial + conditional), got %d", inReleaseCalls.Load())
	}
	// Both should have the same package data.
	if len(idx1.ByArch["amd64"]) != len(idx2.ByArch["amd64"]) {
		t.Fatal("cached and fresh index disagree on package count")
	}
}

// TestFetchIndexFastFallbackTimeoutBoundsHangingUpstream proves a hung
// upstream (as opposed to one that errors quickly, like
// TestFetchIndexStaleFallbackOnError) degrades to the stale fallback within
// fastFallbackTimeout instead of the full retry budget NewHTTPClient
// otherwise allows (up to ~4 attempts x 30s each) -- but only when the
// caller's context is marked via WithClientWaiting, matching the one real
// caller that ever sets it (a /live cold start). See
// TestFetchIndexBackgroundCallerUsesFullRetryBudget for the unmarked case.
func TestFetchIndexFastFallbackTimeoutBoundsHangingUpstream(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)

	var hang atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hang.Load() {
			<-r.Context().Done()
			return
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
	cache := upstream.NewIndexCache()
	f := upstream.NewFetcherWithCache(src, upstream.NewHTTPClient("", ""), cache)
	ctx := upstream.WithClientWaiting(context.Background())

	// First fetch succeeds and warms the cache with real archPkgs.
	idx1, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Force revalidation next time, then make the upstream hang instead of
	// erroring quickly.
	cache.ExpireAll()
	hang.Store(true)

	start := time.Now()
	idx2, err := f.FetchIndex(ctx)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected stale fallback, got error: %v", err)
	}
	if elapsed > 40*time.Second {
		t.Fatalf("expected fastFallbackTimeout (~30s) to bound the hung request, took %v instead", elapsed)
	}
	if len(idx2.ByArch["amd64"]) != len(idx1.ByArch["amd64"]) {
		t.Fatal("stale fallback returned wrong package data")
	}
}

// TestFetchIndexBackgroundCallerToleratesSlowUpstream is the regression test
// for the actual production bug: an unmarked context (the periodic
// refresher, a background /live rebuild -- neither has a client waiting on
// it) must NOT be downgraded to fastFallbackTimeout just because a stale
// fallback exists. The upstream here is slow, not permanently hung
// (NewHTTPClient's own ResponseHeaderTimeout is also 30s, so a permanently
// hung upstream is indistinguishable between the two paths -- it just proves
// nothing either way); a real mirror that's merely slower than
// fastFallbackTimeout, but still answers, is exactly the shape of the
// production incident (real archive/ports mirrors, not an outage). If the
// unmarked path were still (wrongly) bounded by fastFallbackTimeout, this
// fetch would fail over to stale data at ~30s instead of waiting for the
// real, fresh response.
func TestFetchIndexBackgroundCallerToleratesSlowUpstream(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)

	var slow atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(srvURL + r.RequestURI)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		// Headers/status flushed immediately either way -- NewHTTPClient's
		// ResponseHeaderTimeout only bounds waiting for these, so a slow
		// *body* (the realistic shape of a real mirror under load) is what
		// exercises fastFallbackTimeout/the caller's own context, not that
		// separate, already-satisfied timeout.
		w.WriteHeader(resp.StatusCode)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		if slow.Load() {
			select {
			case <-time.After(35 * time.Second):
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	src := makeSource(t, srv.URL, keyring)
	cache := upstream.NewIndexCache()
	f := upstream.NewFetcherWithCache(src, upstream.NewHTTPClient("", ""), cache)

	// Deliberately not WithClientWaiting -- this mirrors the periodic
	// refresher / background rebuild callers.
	bg := context.Background()

	idx1, err := f.FetchIndex(bg)
	if err != nil {
		t.Fatal(err)
	}

	cache.ExpireAll()
	slow.Store(true)

	// Generous outer deadline: the point of this test is that nothing
	// *internal* cuts this off early, not that it's unbounded forever.
	ctx, cancel := context.WithTimeout(bg, 55*time.Second)
	defer cancel()

	start := time.Now()
	idx2, err := f.FetchIndex(ctx)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected the background caller to wait out the slow upstream and succeed, got error: %v", err)
	}
	if elapsed < 33*time.Second {
		t.Fatalf("expected the unmarked background context to wait past fastFallbackTimeout (30s) for the real response, returned early at %v", elapsed)
	}
	if len(idx2.ByArch["amd64"]) != len(idx1.ByArch["amd64"]) {
		t.Fatal("fetched index returned wrong package data")
	}
}

func TestFetchIndexStaleFallbackOnError(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)

	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
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
	cache := upstream.NewIndexCache()
	f := upstream.NewFetcherWithCache(src, &http.Client{}, cache)
	ctx := context.Background()

	// First fetch succeeds and warms the cache.
	idx1, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Now make the upstream fail.
	fail.Store(true)

	// Should return stale cached data rather than error.
	idx2, err := f.FetchIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx1.ByArch["amd64"]) != len(idx2.ByArch["amd64"]) {
		t.Fatal("stale fallback returned wrong package data")
	}
}

// TestFetchSourcesStaleFallbackOnDownloadError proves FetchSources falls back
// to its cached srcs when the Sources file download itself fails (as opposed
// to InRelease failing, which TestFetchIndexStaleFallbackOnError's FetchIndex
// analog covers) -- this specific fallback was missing entirely before: the
// download loop returned the network error straight to the caller with no
// stale-data fallback at all, unlike FetchIndex's per-arch Packages fallback.
func TestFetchSourcesStaleFallbackOnDownloadError(t *testing.T) {
	key, keyring := testKey(t)

	packagesContent := []byte("Package: hello\nVersion: 1.0\nArchitecture: amd64\n")
	var pkgGZBuf bytes.Buffer
	pkgGZ := gzip.NewWriter(&pkgGZBuf)
	if _, err := pkgGZ.Write(packagesContent); err != nil {
		t.Fatal(err)
	}
	if err := pkgGZ.Close(); err != nil {
		t.Fatal(err)
	}
	packagesSum := sha256.Sum256(pkgGZBuf.Bytes())

	sourcesContentA := []byte("Package: hello\nVersion: 1.0\nDirectory: pool/main/h/hello\n")
	sourcesContentB := []byte("Package: hello\nVersion: 2.0\nDirectory: pool/main/h/hello\n")
	sumA := sha256.Sum256(sourcesContentA)
	sumB := sha256.Sum256(sourcesContentB)

	buildInRelease := func(sourcesSum [32]byte, sourcesLen int) []byte {
		releaseBytes := []byte(fmt.Sprintf(
			"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.gz\n %s %d main/source/Sources\n",
			hex.EncodeToString(packagesSum[:]), pkgGZBuf.Len(),
			hex.EncodeToString(sourcesSum[:]), sourcesLen,
		))
		inRelease, err := key.SignInline(releaseBytes)
		if err != nil {
			t.Fatal(err)
		}
		return inRelease
	}
	inReleaseA := buildInRelease(sumA, len(sourcesContentA))
	inReleaseB := buildInRelease(sumB, len(sourcesContentB))

	var useVersionB, sourcesFail atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		// no-cache forces revalidation on every call instead of the 5-minute
		// no-headers fallback expiry letting the second round's FetchIndex/
		// FetchSources skip the network (and so never see version B) via the
		// "still fresh" fast path.
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if useVersionB.Load() {
			_, _ = w.Write(inReleaseB)
		} else {
			_, _ = w.Write(inReleaseA)
		}
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pkgGZBuf.Bytes())
	})
	mux.HandleFunc("/dists/trixie/main/source/Sources", func(w http.ResponseWriter, _ *http.Request) {
		if sourcesFail.Load() {
			// Simulate a genuine transport-level failure (matching the
			// production "timeout awaiting response headers" symptom) rather
			// than an HTTP status -- a bad status for one variant is treated
			// as "try the next variant" by fetchSourcesFile, not a hard
			// failure, so it wouldn't exercise the fallback this test targets.
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sourcesContentA)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	src := makeSource(t, srv.URL, keyring)
	cache := upstream.NewIndexCache()
	f := upstream.NewFetcherWithCache(src, &http.Client{}, cache)
	ctx := context.Background()

	// Warm the cache with version A.
	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}
	srcs1, err := f.FetchSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs1) == 0 || srcs1[0].Version != "1.0" {
		t.Fatalf("expected version 1.0 source entry, got %+v", srcs1)
	}

	// Upstream now publishes version B (a new Sources SHA256, forcing past
	// the "unchanged" fast path) but the Sources file endpoint itself starts
	// failing -- simulating exactly the observed production symptom (a
	// mirror timing out mid-download after InRelease already succeeded).
	useVersionB.Store(true)
	sourcesFail.Store(true)
	if _, err := f.FetchIndex(ctx); err != nil {
		t.Fatal(err)
	}

	srcs2, err := f.FetchSources(ctx)
	if err != nil {
		t.Fatalf("expected stale fallback instead of a hard error, got: %v", err)
	}
	if len(srcs2) == 0 || srcs2[0].Version != "1.0" {
		t.Fatalf("expected stale version 1.0 fallback, got %+v", srcs2)
	}
}

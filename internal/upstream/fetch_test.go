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

func TestDownloadDeb(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, debContent := buildFakeUpstream(t, key)

	src := makeSource(t, srvURL, keyring)
	f := upstream.NewFetcher(src, nil)

	debSum := sha256.Sum256(debContent)
	debSHA256 := hex.EncodeToString(debSum[:])

	got, err := f.DownloadDeb(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb", debSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, debContent) {
		t.Fatal("downloaded content does not match original")
	}
}

func TestDownloadDebBadDigest(t *testing.T) {
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)

	src := makeSource(t, srvURL, keyring)
	f := upstream.NewFetcher(src, nil)

	_, err := f.DownloadDeb(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb", "badhash")
	if err == nil {
		t.Fatal("expected error on SHA256 mismatch")
	}
}

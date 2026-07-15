package server

import (
	"bytes"
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

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/upstream"
)

// testSigningKey generates an in-memory OpenPGP key pair for signing a fake
// upstream's InRelease, mirroring internal/avail's own testKey helper (not
// importable directly -- test files aren't part of either package's
// importable API).
func testSigningKey(t *testing.T) (*signing.Key, openpgp.EntityList) {
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

// buildRebuildLiveTestUpstream serves a minimal signed repo (one package,
// "hello" 1.0) for suite "trixie", component "main", arch "amd64", and
// counts every request it receives.
func buildRebuildLiveTestUpstream(t *testing.T, key *signing.Key) (srvURL string, calls *atomic.Int32) {
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

// TestRebuildLiveSkipsExpensiveWorkWhenUpstreamUnchanged is the direct
// regression test for the "why does it redo everything anyway" fix:
// rebuildLive must not call avail.Build (let alone generateLiveFiles) at
// all on a cycle where every upstream's Release file digests are identical
// to what produced the entry already cached -- checked here via the
// upstream's own request counter, which must not move at all on the second
// call, not even for a lightweight conditional-GET-style re-check.
func TestRebuildLiveSkipsExpensiveWorkWhenUpstreamUnchanged(t *testing.T) {
	key, keyring := testSigningKey(t)
	srvURL, calls := buildRebuildLiveTestUpstream(t, key)

	cfg := &config.Config{
		ResolvedLayouts: []model.Layout{{
			OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"},
			Upstreams: []model.UpstreamSource{{
				Name: "test-upstream", URL: srvURL, Suite: "trixie", Component: "main",
				Archs: []string{"amd64"}, VerifyKeys: keyring,
			}},
		}},
	}
	s := New(cfg, nil, nil, nil, http.DefaultClient, upstream.NewIndexCache(), nil, nil)

	cacheKey := "debian/trixie"
	wait1 := make(chan struct{})
	s.liveBuilding[cacheKey] = wait1
	s.rebuildLive("debian", "trixie", cacheKey, wait1)

	s.mu.Lock()
	first, ok := s.liveCache[cacheKey]
	s.mu.Unlock()
	if !ok {
		t.Fatal("expected an entry after the first rebuildLive call")
	}
	if first.fingerprint == "" {
		t.Fatal("expected the first build to record a non-empty fingerprint")
	}
	callsAfterFirst := calls.Load()
	if callsAfterFirst == 0 {
		t.Fatal("expected the first rebuildLive call to have made at least one real request")
	}
	firstBuilt := first.built

	wait2 := make(chan struct{})
	s.liveBuilding[cacheKey] = wait2
	s.rebuildLive("debian", "trixie", cacheKey, wait2)

	if calls.Load() != callsAfterFirst {
		t.Fatalf("second rebuildLive call made %d additional upstream request(s), want 0 -- it should never have called avail.Build at all", calls.Load()-callsAfterFirst)
	}

	s.mu.Lock()
	second, ok := s.liveCache[cacheKey]
	_, stillBuilding := s.liveBuilding[cacheKey]
	s.mu.Unlock()
	if !ok {
		t.Fatal("expected an entry to still be present after the second rebuildLive call")
	}
	if stillBuilding {
		t.Fatal("expected liveBuilding to be cleared on the unchanged fast path")
	}
	if second.fingerprint != first.fingerprint {
		t.Fatal("fingerprint changed even though the upstream never did")
	}
	if !second.built.After(firstBuilt) {
		t.Fatal("expected the second call to still record a later built time, even though it skipped rebuilding")
	}
}

// TestRebuildLiveKeepsExistingEntryOnUpstreamFetchFailure is the direct
// regression test for avail.Available.HasFetchFailure: when the configured
// upstream is entirely unreachable (not a partial per-arch hiccup -- the
// whole fetch fails, with nothing cached locally yet for this fresh
// IndexCache, so QuickFingerprint's fast path can't apply either) and a
// good entry is already cached, rebuildLive must keep serving that good
// entry (with a freshly extended expiry) rather than swap in whatever
// avail.Build produced -- which, with the only upstream unreachable, would
// have no packages in it at all.
func TestRebuildLiveKeepsExistingEntryOnUpstreamFetchFailure(t *testing.T) {
	cfg := &config.Config{
		ResolvedLayouts: []model.Layout{{
			OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"},
			Upstreams: []model.UpstreamSource{{
				// Nothing listens here -- guaranteed connection failure.
				Name: "test-upstream", URL: "http://127.0.0.1:1", Suite: "trixie", Component: "main",
				Archs: []string{"amd64"},
			}},
		}},
	}
	s := New(cfg, nil, nil, nil, http.DefaultClient, upstream.NewIndexCache(), nil, nil)

	cacheKey := "debian/trixie"
	goodEntry := &liveEntry{
		files:       map[string][]byte{"dists/trixie/main/binary-amd64/Packages": []byte("Package: hello\nVersion: 1.0\n")},
		hashes:      map[string]string{"dists/trixie/main/binary-amd64/Packages": "deadbeef"},
		built:       time.Now().Add(-time.Hour),
		expiry:      time.Now().Add(-time.Minute), // stale, deliberately -- this is what triggers a rebuild attempt
		fingerprint: "arbitrary-fingerprint-that-nothing-will-match",
	}
	s.liveCache[cacheKey] = goodEntry

	wait := make(chan struct{})
	s.liveBuilding[cacheKey] = wait
	s.rebuildLive("debian", "trixie", cacheKey, wait)

	s.mu.Lock()
	after, ok := s.liveCache[cacheKey]
	_, stillBuilding := s.liveBuilding[cacheKey]
	s.mu.Unlock()

	if !ok {
		t.Fatal("expected an entry to still be present")
	}
	if stillBuilding {
		t.Fatal("expected liveBuilding to be cleared")
	}
	if string(after.files["dists/trixie/main/binary-amd64/Packages"]) != "Package: hello\nVersion: 1.0\n" {
		t.Fatal("expected the previous good entry's files to still be served, not replaced by an incomplete build")
	}
	if !after.built.After(goodEntry.built) {
		t.Fatal("expected built to still be refreshed even though the content was kept")
	}
	if !after.expiry.After(time.Now()) {
		t.Fatal("expected expiry to be extended into the future, not left in the past")
	}
}

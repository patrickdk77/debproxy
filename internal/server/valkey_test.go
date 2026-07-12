package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/server"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storagefactory"
	"github.com/debproxy/debproxy/internal/testsupport"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// testValkeyAddr is set by TestMain once the shared container is up.
var testValkeyAddr string

// TestMain starts one real Valkey container for the whole test binary run
// (see testsupport.StartValkey for why a real server rather than a mock).
func TestMain(m *testing.M) {
	testsupport.RunMain(m, &testValkeyAddr)
}

func newRawTestClient(t *testing.T) valkey.Client {
	return testsupport.NewTestClient(t, testValkeyAddr)
}

// testLiveMeta mirrors the unexported server.liveMeta shape structurally --
// encoding/json matches by field name, not by type identity, so this works
// without needing access to the real (unexported) type.
type testLiveMeta struct {
	BuiltAt time.Time
	Expiry  time.Time
	Hashes  map[string]string
}

// TestLive_AdoptsCompressedArtifactsFromValkey proves the core Phase 4
// claim: a second replica (its own Server instance, its own empty local
// liveCache) serves the exact bytes another replica already published to
// Valkey rather than independently recompressing. It does this
// deterministically by overwriting the published artifact's bytes with a
// sentinel value after the first replica builds it -- if the second replica
// served the sentinel back, it must have adopted rather than rebuilt (a
// fresh local build would produce the real compressed content, never the
// sentinel).
func TestLiveAdoptsCompressedArtifactsFromValkey(t *testing.T) {
	dir := t.TempDir()

	upstreamPriv := filepath.Join(dir, "upstream.priv.asc")
	upstreamPub := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, upstreamPriv, upstreamPub)
	repoPriv := filepath.Join(dir, "repo.priv.asc")
	writeKeyPair(t, repoPriv, "")

	upstreamKey, err := signing.Load(upstreamPriv)
	if err != nil {
		t.Fatal(err)
	}

	helloControl := "Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: hello\n"
	helloDeb := buildDeb(t, helloControl)
	helloUpstreamPath := "pool/main/h/hello/hello_1.0_amd64.deb"

	files := map[string][]byte{}
	packagesContent := packagesStanza(t, helloControl, helloUpstreamPath, helloDeb)
	packagesGz := gzipBytes(t, packagesContent)
	files["/"+helloUpstreamPath] = helloDeb
	files["/dists/trixie/main/binary-amd64/Packages"] = packagesContent
	files["/dists/trixie/main/binary-amd64/Packages.gz"] = packagesGz

	release := buildUpstreamRelease(packagesContent, packagesGz)
	inRelease, err := upstreamKey.SignInline([]byte(release))
	if err != nil {
		t.Fatal(err)
	}
	files["/dists/trixie/InRelease"] = inRelease

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstreamSrv.Close()

	cfgPath := filepath.Join(dir, "config.yaml")
	writeConfig(t, cfgPath, dir, upstreamSrv.URL, upstreamPub, repoPriv)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storagefactory.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb822store.New(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := signing.Load(repoPriv)
	if err != nil {
		t.Fatal(err)
	}

	rawClient := newRawTestClient(t)
	keys := valkeycache.Keys{Prefix: "test-live-adopt:"}
	ctx := context.Background()
	const liveGzURL = "/live/debian/dists/trixie/main/binary-amd64/Packages.gz"

	// Replica 1: cold-start build, publishes to Valkey.
	server1 := server.New(cfg, store, index, repoKey, nil, nil, nil, nil)
	stop1 := server1.EnableValkey(ctx, rawClient, keys)
	defer stop1()
	srv1 := httptest.NewServer(server1.Handler())
	defer srv1.Close()

	original := httpGet(t, srv1.URL+liveGzURL)
	if len(original) == 0 {
		t.Fatal("expected non-empty Packages.gz from replica 1")
	}

	// Discover the exact relpath key generateLiveFiles used, then overwrite
	// its stored bytes with a sentinel value distinguishable from any real
	// compression output.
	metaStr, err := rawClient.Do(ctx, rawClient.B().Get().Key(keys.LiveMeta("debian", "trixie")).Build()).ToString()
	if err != nil {
		t.Fatalf("read live meta: %v", err)
	}
	var meta testLiveMeta
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		t.Fatalf("decode live meta: %v", err)
	}
	var gzRelPath string
	for relpath := range meta.Hashes {
		if filepath.Ext(relpath) == ".gz" {
			gzRelPath = relpath
			break
		}
	}
	if gzRelPath == "" {
		t.Fatalf("no .gz entry found in published hashes: %+v", meta.Hashes)
	}

	sentinel := []byte("SENTINEL-ADOPTED-FROM-VALKEY-NOT-RECOMPRESSED")
	fileKey := keys.LiveFile("debian", "trixie", gzRelPath)
	if err := rawClient.Do(ctx, rawClient.B().Set().Key(fileKey).Value(string(sentinel)).Build()).Error(); err != nil {
		t.Fatalf("overwrite published file: %v", err)
	}

	// Replica 2: brand new Server, empty local liveCache, same Valkey.
	server2 := server.New(cfg, store, index, repoKey, nil, nil, nil, nil)
	stop2 := server2.EnableValkey(ctx, rawClient, keys)
	defer stop2()
	srv2 := httptest.NewServer(server2.Handler())
	defer srv2.Close()

	got := httpGet(t, srv2.URL+liveGzURL)
	if string(got) != string(sentinel) {
		t.Fatalf("expected replica 2 to adopt the sentinel bytes from valkey, got %d bytes of real content instead", len(got))
	}
}

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/testsupport"
)

func TestResolveByHash_FindsCurrentAndRetiredGenerations(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)

	oldKey := "dists/trixie/main/binary-amd64/Packages.gz"
	old := &liveEntry{
		files:  map[string][]byte{oldKey: []byte("old-bytes")},
		hashes: map[string]string{oldKey: "oldhash"},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	s.swapLiveEntry("debian", "trixie", old, false)

	newKey := "dists/trixie/main/binary-amd64/Packages.gz"
	newer := &liveEntry{
		files:  map[string][]byte{newKey: []byte("new-bytes")},
		hashes: map[string]string{newKey: "newhash"},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	s.swapLiveEntry("debian", "trixie", newer, false)

	// The old generation's hash must still resolve, even though it's no
	// longer current -- this is what lets a client that already read the
	// old Release keep fetching by that hash after a rebuild.
	data, _, ok := s.resolveByHash("debian", "trixie", newer, "oldhash")
	if !ok {
		t.Fatal("expected the retired generation's hash to still resolve")
	}
	if string(data) != "old-bytes" {
		t.Fatalf("got %q, want %q", data, "old-bytes")
	}

	// The current generation's own hash resolves directly, without needing
	// the retired list at all.
	if data, _, ok := s.resolveByHash("debian", "trixie", newer, "newhash"); !ok || string(data) != "new-bytes" {
		t.Fatalf("got ok=%v data=%q, want the current generation's bytes", ok, data)
	}

	// A completely unrelated cacheKey must not see debian/trixie's retirees.
	if _, _, ok := s.resolveByHash("ubuntu", "noble", &liveEntry{hashes: map[string]string{}}, "oldhash"); ok {
		t.Fatal("expected retired entries to be scoped per os/codename")
	}
}

func TestResolveByHash_RespectsRetentionWindow(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	cacheKey := "debian/trixie"
	current := &liveEntry{hashes: map[string]string{}} // no match in current; forces the retired-list path

	s.mu.Lock()
	s.retiredLive[cacheKey] = []*retiredLiveEntry{
		{
			entry: &liveEntry{
				files:  map[string][]byte{"stale-key": []byte("stale")},
				hashes: map[string]string{"stale-key": "stalehash"},
			},
			retiredAt: time.Now().Add(-liveRetiredRetention - time.Second), // just past the window
		},
		{
			entry: &liveEntry{
				files:  map[string][]byte{"fresh-key": []byte("fresh")},
				hashes: map[string]string{"fresh-key": "freshhash"},
			},
			retiredAt: time.Now().Add(-time.Second), // well within the window
		},
	}
	s.mu.Unlock()

	if _, _, ok := s.resolveByHash("debian", "trixie", current, "stalehash"); ok {
		t.Fatal("expected a hash retired past the retention window to be unresolvable")
	}
	if data, _, ok := s.resolveByHash("debian", "trixie", current, "freshhash"); !ok || string(data) != "fresh" {
		t.Fatalf("expected the recently retired hash to still resolve, got ok=%v data=%q", ok, data)
	}
}

func TestLiveEntry_LookupByHash(t *testing.T) {
	e := &liveEntry{
		files:  map[string][]byte{"main/binary-amd64/Packages.gz": []byte("content")},
		hashes: map[string]string{"main/binary-amd64/Packages.gz": "somehash"},
	}
	data, plainKey, ok := e.lookupByHash("somehash")
	if !ok || string(data) != "content" || plainKey != "main/binary-amd64/Packages.gz" {
		t.Fatalf("got ok=%v data=%q plainKey=%q", ok, data, plainKey)
	}
	if _, _, ok := e.lookupByHash("nonexistent"); ok {
		t.Fatal("expected no match for an unknown hash")
	}
}

func TestHashFromByHashKey(t *testing.T) {
	cases := map[string]string{
		"main/binary-amd64/by-hash/SHA256/abc123": "abc123",
		"main/source/by-hash/SHA256/deadbeef":     "deadbeef",
		"main/binary-amd64/Packages.gz":           "",
		"":                                        "",
	}
	for key, want := range cases {
		if got := hashFromByHashKey(key); got != want {
			t.Errorf("hashFromByHashKey(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestHandleLive_ServesRetiredGenerationByHashFile is the end-to-end
// regression test for the reported bug: an apt client that already read
// Release (and so already knows a specific by-hash path) must still be able
// to fetch it after this replica's /live view rebuilds to a newer
// generation, for as long as the retention window allows.
func TestHandleLive_ServesRetiredGenerationByHashFile(t *testing.T) {
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	const plainKey = "dists/trixie/main/binary-amd64/Packages.gz"
	old := &liveEntry{
		files:  map[string][]byte{plainKey: []byte("old-generation-bytes")},
		hashes: map[string]string{plainKey: "deadbeef"},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	s.swapLiveEntry("debian", "trixie", old, false)

	// A newer generation supersedes it, with different content (and so a
	// different hash) at the *same* plain-named path -- the old hash is not
	// present in the new generation's hashes at all.
	newer := &liveEntry{
		files:  map[string][]byte{plainKey: []byte("new-generation-bytes")},
		hashes: map[string]string{plainKey: "newhash"},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	s.swapLiveEntry("debian", "trixie", newer, false)

	resp, err := http.Get(srv.URL + "/live/debian/dists/trixie/main/binary-amd64/by-hash/SHA256/deadbeef")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200 -- the superseded generation's by-hash file should still be servable", resp.StatusCode)
	}
	body := make([]byte, 64)
	n, _ := resp.Body.Read(body)
	if got := string(body[:n]); got != "old-generation-bytes" {
		t.Fatalf("got body %q, want the retired generation's own bytes", got)
	}
	if etag := resp.Header.Get("ETag"); etag != `"deadbeef"` {
		t.Fatalf("got ETag %q, want the hash extracted from the by-hash path itself", etag)
	}
}

// TestHandleLive_ByHashMissEverywhereReturns404 confirms a by-hash request
// that matches neither the current generation nor any still-retained
// retired one 404s outright -- there's no decompression-fallback equivalent
// for a by-hash request the way there is for a plain-named one.
func TestHandleLive_ByHashMissEverywhereReturns404(t *testing.T) {
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	entry := &liveEntry{
		files:  map[string][]byte{"dists/trixie/main/binary-amd64/Packages.gz": []byte("bytes")},
		hashes: map[string]string{"dists/trixie/main/binary-amd64/Packages.gz": "realhash"},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	s.swapLiveEntry("debian", "trixie", entry, false)

	resp, err := http.Get(srv.URL + "/live/debian/dists/trixie/main/binary-amd64/by-hash/SHA256/nonexistent")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", resp.StatusCode)
	}
}

// TestGenerateLiveFiles_NoByHashDuplicates is the regression test for the
// memory/peer-fetch duplication bug: generateLiveFiles must never produce a
// literal by-hash-named entry (that would be an exact duplicate of a
// plain-named entry's bytes -- see SkipByHash and liveEntry.lookupByHash),
// while by-hash requests must still resolve correctly via the hashes index
// it does produce.
func TestGenerateLiveFiles_NoByHashDuplicates(t *testing.T) {
	cfg := &config.Config{
		ResolvedLayouts: []model.Layout{
			{OS: "debian", Codename: "trixie", Component: "main", Archs: []string{"amd64"}, HashTypes: []string{"sha256"}},
		},
	}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)
	av := &avail.Available{OS: "debian", Codename: "trixie"}

	files, hashes, err := s.generateLiveFiles(context.Background(), av)
	if err != nil {
		t.Fatalf("generateLiveFiles: %v", err)
	}
	for key := range files {
		if strings.Contains(key, "/by-hash/") {
			t.Errorf("generateLiveFiles produced a literal by-hash entry %q; by-hash must be resolved virtually, not stored", key)
		}
	}
	if len(hashes) == 0 {
		t.Fatal("expected hashes to be populated from Release for by-hash resolution")
	}

	entry := &liveEntry{files: files, hashes: hashes}
	for key, hash := range hashes {
		if _, ok := files[key]; !ok {
			continue // the "plain" (uncompressed) entry: hashed for Release, but never actually stored -- see buildRelease
		}
		data, plainKey, ok := entry.lookupByHash(hash)
		if !ok || plainKey != key {
			t.Errorf("lookupByHash(%q) = ok=%v plainKey=%q, want key %q", hash, ok, plainKey, key)
		}
		if string(data) != string(files[key]) {
			t.Errorf("lookupByHash(%q) returned different bytes than files[%q]", hash, key)
		}
	}
}

func TestSwapLiveEntry_PublishesOnlyWhenFresh(t *testing.T) {
	client := testsupport.NewTestClient(t, TestValkeyAddr)
	// A real port, not ":0": publishLiveUpdate skips publishing entirely
	// when it has no peerAddrs to advertise (see localPeerAddrs), and ":0"
	// has no determinable port for that purpose.
	s := newValkeyEnabledServer(t, ":18080")

	received := make(chan struct{}, 2)
	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = client.Receive(subCtx, client.B().Subscribe().Channel("events:live-updated").Build(),
			func(valkey.PubSubMessage) { received <- struct{}{} })
	}()
	time.Sleep(200 * time.Millisecond) // let the subscription establish

	entry := &liveEntry{
		files:  map[string][]byte{"k": []byte("v")},
		hashes: map[string]string{},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}

	// fresh=false (peer-adopted): must not publish.
	s.swapLiveEntry("debian", "trixie", entry, false)
	select {
	case <-received:
		t.Fatal("did not expect a publish for a peer-adopted (non-fresh) swap")
	case <-time.After(500 * time.Millisecond):
	}

	// fresh=true (locally generated): must publish.
	s.swapLiveEntry("debian", "trixie", entry, true)
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a publish for a freshly-generated swap")
	}
}

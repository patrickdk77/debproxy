package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/testsupport"
)

func testLayoutConfig() *config.Config {
	return &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
}

func newValkeyEnabledServer(t *testing.T, listenAddr string) *Server {
	t.Helper()
	client := testsupport.NewTestClient(t, TestValkeyAddr)
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	stop := s.EnableValkey(context.Background(), client, listenAddr)
	t.Cleanup(stop)
	return s
}

func TestHandleLiveUpdatedMessageInvalidatesMatchingEntry(t *testing.T) {
	// Invalidation is jittered (see liveUpdateInvalidateJitter) -- shrink it
	// so this test doesn't have to wait out the full production window.
	orig := liveUpdateInvalidateJitter
	liveUpdateInvalidateJitter = time.Millisecond
	t.Cleanup(func() { liveUpdateInvalidateJitter = orig })

	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)

	future := time.Now().Add(time.Hour)
	s.liveCache["debian/trixie"] = &liveEntry{expiry: future}
	s.liveCache["ubuntu/noble"] = &liveEntry{expiry: future}

	msg, err := json.Marshal(liveUpdatedMsg{OS: "debian", Codename: "trixie"})
	if err != nil {
		t.Fatal(err)
	}
	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		invalidated := s.liveCache["debian/trixie"].expiry.IsZero()
		s.mu.Unlock()
		if invalidated {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for debian/trixie entry to be invalidated")
		}
		time.Sleep(time.Millisecond)
	}

	s.mu.Lock()
	untouched := s.liveCache["ubuntu/noble"].expiry
	s.mu.Unlock()
	if !untouched.Equal(future) {
		t.Fatal("expected unrelated ubuntu/noble entry to be left untouched")
	}
}

func TestHandleLiveUpdatedMessageNoLocalEntryIsNoop(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)

	msg, err := json.Marshal(liveUpdatedMsg{OS: "debian", Codename: "bookworm"})
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic even though no entry exists for this os/codename.
	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	if len(s.liveCache) != 0 {
		t.Fatalf("expected no entries created, got %v", s.liveCache)
	}
}

func TestHandleLiveUpdatedMessageMalformedMessageIsIgnored(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	future := time.Now().Add(time.Hour)
	s.liveCache["debian/trixie"] = &liveEntry{expiry: future}

	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: "not json"})

	if !s.liveCache["debian/trixie"].expiry.Equal(future) {
		t.Fatal("expected entry to be untouched after a malformed message")
	}
}

// TestBuildOrAdoptLiveFiles_AdoptsFromPeerViaHTTP is the direct regression
// test for the whole peer-fetch redesign: a consumer with no local liveCache
// entry, primed only with a notice pointing at a publisher, must fetch the
// publisher's actual bytes over HTTP rather than building its own. Proven
// deterministically with a sentinel value no real build could ever produce
// -- if the consumer returned it, it was fetched, not generated.
func TestBuildOrAdoptLiveFiles_AdoptsFromPeerViaHTTP(t *testing.T) {
	const fileKey = "dists/trixie/main/binary-amd64/Packages.gz"
	sentinel := []byte("SENTINEL-FROM-PUBLISHER-NOT-RECOMPILED")
	builtAt := time.Now().Truncate(time.Second)
	expiry := builtAt.Add(time.Hour)
	hashes := map[string]string{fileKey: "deadbeef"}

	// Publisher: a cache hit, not a real build -- liveCache is populated
	// directly, so serving it needs no real upstream/metadata machinery.
	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files: map[string][]byte{fileKey: sentinel}, hashes: hashes, built: builtAt, expiry: expiry,
	}
	pubSrv := httptest.NewServer(publisher.Handler())
	defer pubSrv.Close()
	pubAddr := pubSrv.Listener.Addr().String()

	consumer := newValkeyEnabledServer(t, ":0")

	notice := liveUpdatedMsg{
		OS: "debian", Codename: "trixie",
		Addrs:   []string{pubAddr},
		BuiltAt: builtAt, Expiry: expiry,
		Hashes: hashes, Files: []string{fileKey},
	}
	data, err := json.Marshal(notice)
	if err != nil {
		t.Fatalf("marshal notice: %v", err)
	}
	consumer.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(data)})

	av := &avail.Available{}
	files, gotHashes, gotBuiltAt, gotExpiry, fresh, err := consumer.buildOrAdoptLiveFiles(context.Background(), "debian", "trixie", av)
	if err != nil {
		t.Fatalf("buildOrAdoptLiveFiles: %v", err)
	}
	if fresh {
		t.Error("expected fresh=false for a peer-adopted generation")
	}
	if string(files[fileKey]) != string(sentinel) {
		t.Fatalf("files[%q] = %q, want the publisher's sentinel bytes", fileKey, files[fileKey])
	}
	if gotHashes[fileKey] != hashes[fileKey] {
		t.Errorf("hashes[%q] = %q, want %q", fileKey, gotHashes[fileKey], hashes[fileKey])
	}
	if !gotBuiltAt.Equal(builtAt) || !gotExpiry.Equal(expiry) {
		t.Errorf("builtAt/expiry = %v/%v, want %v/%v", gotBuiltAt, gotExpiry, builtAt, expiry)
	}
}

func TestAdoptLiveFromPeer_NoNoticeFails(t *testing.T) {
	s := newValkeyEnabledServer(t, ":0")
	_, _, _, _, ok := s.adoptLiveFromPeer(context.Background(), "debian", "trixie")
	if ok {
		t.Error("adoptLiveFromPeer() with no recorded notice = true, want false")
	}
}

func TestAdoptLiveFromPeer_ExpiredNoticeFails(t *testing.T) {
	s := newValkeyEnabledServer(t, ":0")
	s.valkey.mu.Lock()
	s.valkey.notices["debian/trixie"] = liveUpdatedMsg{
		OS: "debian", Codename: "trixie",
		Addrs: []string{"127.0.0.1:1"}, Files: []string{"x"},
		Expiry: time.Now().Add(-time.Minute), // already expired
	}
	s.valkey.mu.Unlock()

	_, _, _, _, ok := s.adoptLiveFromPeer(context.Background(), "debian", "trixie")
	if ok {
		t.Error("adoptLiveFromPeer() with an expired notice = true, want false")
	}
}

func TestAdoptLiveFromPeer_UnreachablePeerFallsBackToLocal(t *testing.T) {
	s := newValkeyEnabledServer(t, ":0")
	s.valkey.mu.Lock()
	s.valkey.notices["debian/trixie"] = liveUpdatedMsg{
		OS: "debian", Codename: "trixie",
		Addrs:  []string{"127.0.0.1:1"}, // nothing listens here
		Files:  []string{"dists/trixie/main/binary-amd64/Packages.gz"},
		Expiry: time.Now().Add(time.Hour),
	}
	s.valkey.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _, _, ok := s.adoptLiveFromPeer(ctx, "debian", "trixie")
	if ok {
		t.Error("adoptLiveFromPeer() with an unreachable peer = true, want false (fall back to local build)")
	}
}

// TestFetchLiveFiles_TriesEachAddrInTurn confirms a dead first address
// doesn't abort the fetch -- the second, reachable address must still be
// tried and succeed.
func TestFetchLiveFiles_TriesEachAddrInTurn(t *testing.T) {
	const fileKey = "dists/trixie/main/binary-amd64/Packages.gz"
	content := []byte("real content")

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files: map[string][]byte{fileKey: content}, hashes: map[string]string{}, expiry: time.Now().Add(time.Hour),
	}
	pubSrv := httptest.NewServer(publisher.Handler())
	defer pubSrv.Close()

	b := &serverValkeyBacking{peerHTTP: &http.Client{Timeout: 2 * time.Second}}
	notice := liveUpdatedMsg{
		Addrs: []string{"127.0.0.1:1", pubSrv.Listener.Addr().String()}, // first is dead
		Files: []string{fileKey},
	}
	files, err := b.fetchLiveFiles(context.Background(), "debian", notice)
	if err != nil {
		t.Fatalf("fetchLiveFiles: %v", err)
	}
	if string(files[fileKey]) != string(content) {
		t.Errorf("files[%q] = %q, want %q", fileKey, files[fileKey], content)
	}
}

func TestPublishLiveUpdate_SkipsWhenNoPeerAddrs(t *testing.T) {
	client := testsupport.NewTestClient(t, TestValkeyAddr)
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	s.valkey = &serverValkeyBacking{client: client, peerAddrs: nil, notices: map[string]liveUpdatedMsg{}}

	received := make(chan struct{}, 1)
	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = client.Receive(subCtx, client.B().Subscribe().Channel("events:live-updated").Build(),
			func(valkey.PubSubMessage) { received <- struct{}{} })
	}()
	time.Sleep(200 * time.Millisecond) // let the subscription establish

	s.publishLiveUpdate("debian", "trixie", map[string][]byte{"k": []byte("v")}, nil, time.Now(), time.Now().Add(time.Hour))

	select {
	case <-received:
		t.Error("publishLiveUpdate published a notice despite having no peer addresses to advertise")
	case <-time.After(500 * time.Millisecond):
		// expected: nothing published
	}
}

func TestLocalPeerAddrs(t *testing.T) {
	addrs := localPeerAddrs(":8080")
	for _, a := range addrs {
		if a == "" {
			t.Error("localPeerAddrs returned an empty address")
		}
		if got := a[len(a)-5:]; got != ":8080" {
			t.Errorf("address %q does not end in the configured port :8080", a)
		}
		if len(a) >= 9 && a[:9] == "127.0.0.1" {
			t.Errorf("address %q is a loopback address, want it filtered out", a)
		}
	}

	if got := localPeerAddrs("not-a-valid-addr"); got != nil {
		t.Errorf("localPeerAddrs(invalid) = %v, want nil", got)
	}
}

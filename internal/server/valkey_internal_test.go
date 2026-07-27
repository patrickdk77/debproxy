package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// roundTripFunc lets a plain func satisfy http.RoundTripper for tests below.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testLayoutConfig() *config.Config {
	return &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
}

func newValkeyEnabledServer(t *testing.T, listenAddr string) *Server {
	t.Helper()
	client := testsupport.NewTestClient(t, TestValkeyAddr)
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	stop := s.EnableValkey(context.Background(), client, valkeycache.Keys{Prefix: "test:"}, listenAddr, "")
	t.Cleanup(stop)
	return s
}

// TestHandleLiveUpdatedMessageStagesThenPromotes is the end-to-end test for
// the switchover mechanism, and the direct regression test for the
// production failure it exists to fix: with several replicas behind a load
// balancer, apt read InRelease from one replica and fetched the
// Packages.zst it named from another, which had never heard of that
// generation. The by-hash fetch 404'd, apt fell back to the plain-named
// path, and the user saw "File has unexpected size (X != Y). Mirror sync in
// progress?".
//
// The fix is that a peer's new generation becomes fetchable BY HASH on this
// replica as soon as the notice is handled, while the generation this
// replica advertises -- its plain-named paths, and the InRelease naming
// them -- keeps pointing at the old one until the shared deadline. So there
// is no instant at which any replica advertises a generation its peers
// cannot already serve.
func TestHandleLiveUpdatedMessageStagesThenPromotes(t *testing.T) {
	origJitter := liveUpdateInvalidateJitter
	liveUpdateInvalidateJitter = time.Millisecond
	t.Cleanup(func() { liveUpdateInvalidateJitter = origJitter })
	origDelay := liveSwitchoverDelay
	liveSwitchoverDelay = 750 * time.Millisecond
	t.Cleanup(func() { liveSwitchoverDelay = origDelay })

	const (
		pkgKey = "dists/trixie/main/binary-amd64/Packages.gz"
		relKey = "dists/trixie/InRelease"
	)
	newPkgs := []byte("new generation packages")
	sum := sha256.Sum256(newPkgs)
	newHash := hex.EncodeToString(sum[:])

	// The publisher holds the new generation and, crucially, serves it by
	// hash -- which is the only way a peer can name these bytes while the
	// publisher's own plain-named paths still serve its previous ones.
	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files:  map[string][]byte{pkgKey: newPkgs},
		hashes: map[string]string{pkgKey: newHash},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	pubSrv := httptest.NewServer(publisher.Handler())
	defer pubSrv.Close()

	consumer := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	consumer.valkey = &serverValkeyBacking{
		instanceID: "consumer-id",
		notices:    map[string]liveUpdatedMsg{},
		peerHTTP:   &http.Client{Timeout: 2 * time.Second},
	}
	oldPkgs := []byte("old generation packages")
	oldSum := sha256.Sum256(oldPkgs)
	oldHash := hex.EncodeToString(oldSum[:])
	original := &liveEntry{
		files:  map[string][]byte{pkgKey: oldPkgs, relKey: []byte("old InRelease")},
		hashes: map[string]string{pkgKey: oldHash},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	consumer.liveCache["debian/trixie"] = original

	msg, err := json.Marshal(liveUpdatedMsg{
		OS: "debian", Codename: "trixie",
		Addrs:    []string{pubSrv.Listener.Addr().String()},
		BuiltAt:  time.Now(),
		Expiry:   time.Now().Add(time.Hour),
		Hashes:   map[string]string{pkgKey: newHash},
		Files:    []string{pkgKey, relKey},
		Unhashed: map[string][]byte{relKey: []byte("new InRelease")},
		SourceID: "publisher-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	// Phase 1: staged. The new generation answers by hash, but the served
	// generation has not moved.
	staged := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		consumer.mu.Lock()
		_, staged = consumer.stagedLive["debian/trixie"]
		consumer.mu.Unlock()
		if staged {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !staged {
		t.Fatal("timed out waiting for the peer's generation to be staged")
	}

	consumer.mu.Lock()
	current := consumer.liveCache["debian/trixie"]
	consumer.mu.Unlock()
	if current != original {
		t.Fatal("the peer's generation was promoted immediately; it must stay staged until the shared deadline, or this replica starts advertising bytes its peers may not have yet")
	}
	data, _, ok := consumer.resolveByHash("debian", "trixie", current, newHash)
	if !ok {
		t.Fatal("the staged generation's hash must resolve before promotion -- this is the whole point of staging")
	}
	if string(data) != string(newPkgs) {
		t.Fatalf("staged by-hash lookup = %q, want %q", data, newPkgs)
	}
	// The outgoing generation stays resolvable by hash throughout.
	if _, _, ok := consumer.resolveByHash("debian", "trixie", current, oldHash); !ok {
		t.Error("the current generation's hash stopped resolving while a newer one was staged")
	}

	// Phase 2: promoted at the deadline.
	promoted := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		consumer.mu.Lock()
		promoted = consumer.liveCache["debian/trixie"] != original
		consumer.mu.Unlock()
		if promoted {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !promoted {
		t.Fatal("timed out waiting for the staged generation to be promoted at the switchover deadline")
	}

	consumer.mu.Lock()
	now := consumer.liveCache["debian/trixie"]
	_, stillStaged := consumer.stagedLive["debian/trixie"]
	consumer.mu.Unlock()
	if stillStaged {
		t.Error("staging slot was not cleared on promotion")
	}
	if string(now.files[pkgKey]) != string(newPkgs) {
		t.Errorf("promoted files[%q] = %q, want the peer's bytes %q", pkgKey, now.files[pkgKey], newPkgs)
	}
	// Release/InRelease have no by-hash url, so they ride inside the
	// notice; the promoted generation must carry the peer's copy, not the
	// one this replica had before.
	if string(now.files[relKey]) != "new InRelease" {
		t.Errorf("promoted files[%q] = %q, want the peer's inline copy", relKey, now.files[relKey])
	}
	// And the generation it replaced stays fetchable by hash for clients
	// still holding its Release.
	if _, _, ok := consumer.resolveByHash("debian", "trixie", now, oldHash); !ok {
		t.Error("the superseded generation must remain resolvable by hash after promotion")
	}
}

// TestHandleLiveUpdatedMessageAdoptsDespiteUnchangedUpstream is the
// regression test for why adoption must not route through rebuildLive.
// rebuildLive opens with a QuickFingerprint check and, when upstream
// Release digests are unchanged, returns early with nothing but an expiry
// extension. Adoption used to go through it, so a replica whose own
// generation came from the same upstream data as the publisher's declined
// to adopt, kept serving its own byte-divergent generation, and extended
// its expiry -- which meant it never reconsidered either. Replicas drifted
// apart permanently, and the drift got worse the longer the process ran.
func TestHandleLiveUpdatedMessageAdoptsDespiteUnchangedUpstream(t *testing.T) {
	origJitter := liveUpdateInvalidateJitter
	liveUpdateInvalidateJitter = time.Millisecond
	t.Cleanup(func() { liveUpdateInvalidateJitter = origJitter })
	origDelay := liveSwitchoverDelay
	liveSwitchoverDelay = time.Millisecond
	t.Cleanup(func() { liveSwitchoverDelay = origDelay })

	const pkgKey = "dists/trixie/main/binary-amd64/Packages.gz"
	peerPkgs := []byte("the publisher's bytes")
	sum := sha256.Sum256(peerPkgs)
	peerHash := hex.EncodeToString(sum[:])

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files:  map[string][]byte{pkgKey: peerPkgs},
		hashes: map[string]string{pkgKey: peerHash},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	pubSrv := httptest.NewServer(publisher.Handler())
	defer pubSrv.Close()

	consumer := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	consumer.valkey = &serverValkeyBacking{
		instanceID: "consumer-id",
		notices:    map[string]liveUpdatedMsg{},
		peerHTTP:   &http.Client{Timeout: 2 * time.Second},
	}
	// Same fingerprint the publisher would compute: upstream has not moved
	// at all. Under the old code path this is exactly what made the replica
	// skip the adopt.
	original := &liveEntry{
		files:       map[string][]byte{pkgKey: []byte("this replica's own divergent bytes")},
		hashes:      map[string]string{pkgKey: "localhash"},
		built:       time.Now(),
		expiry:      time.Now().Add(time.Hour),
		fingerprint: "identical-upstream-fingerprint",
	}
	consumer.liveCache["debian/trixie"] = original

	msg, err := json.Marshal(liveUpdatedMsg{
		OS: "debian", Codename: "trixie",
		Addrs:    []string{pubSrv.Listener.Addr().String()},
		BuiltAt:  time.Now(),
		Expiry:   time.Now().Add(time.Hour),
		Hashes:   map[string]string{pkgKey: peerHash},
		Files:    []string{pkgKey},
		SourceID: "publisher-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		consumer.mu.Lock()
		got := consumer.liveCache["debian/trixie"]
		consumer.mu.Unlock()
		if string(got.files[pkgKey]) == string(peerPkgs) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("replica did not adopt the peer's generation when upstream was unchanged -- it will keep serving byte-divergent indexes, and by-hash fetches load-balanced across replicas will 404")
}

// TestHandleLiveUpdatedMessageIgnoresOwnNotice is the direct regression test
// for the production incident where a replica downloaded its own files: since
// EnableValkey subscribes to the exact channel it also publishes on, a
// replica always receives its own live-updated notice back. Before SourceID
// filtering, the proactive-adopt jitter timer would still fire on that
// self-notice, invalidate the entry the replica had itself just built, and
// then "adopt" it right back from its own advertised address over real HTTP.
func TestHandleLiveUpdatedMessageIgnoresOwnNotice(t *testing.T) {
	orig := liveUpdateInvalidateJitter
	liveUpdateInvalidateJitter = time.Millisecond
	t.Cleanup(func() { liveUpdateInvalidateJitter = orig })

	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	s.valkey = &serverValkeyBacking{instanceID: "self-id", notices: map[string]liveUpdatedMsg{}}

	future := time.Now().Add(time.Hour)
	original := &liveEntry{expiry: future}
	s.liveCache["debian/trixie"] = original

	msg, err := json.Marshal(liveUpdatedMsg{OS: "debian", Codename: "trixie", SourceID: "self-id"})
	if err != nil {
		t.Fatal(err)
	}
	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	// Give a wrongly-scheduled proactive adopt time to fire if the filter
	// didn't work, then confirm nothing changed.
	time.Sleep(50 * time.Millisecond)

	s.mu.Lock()
	untouched := s.liveCache["debian/trixie"] == original
	_, pending := s.pendingPeerAdopt["debian/trixie"]
	s.mu.Unlock()
	if !untouched {
		t.Error("own notice triggered a proactive rebuild of the entry this replica just built")
	}
	if pending {
		t.Error("own notice registered a pending peer-adopt timer, want it ignored outright")
	}

	s.valkey.mu.Lock()
	_, stored := s.valkey.notices["debian/trixie"]
	s.valkey.mu.Unlock()
	if stored {
		t.Error("own notice was stored in the notices map, want it ignored before storage")
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

// TestGetLiveDefersToPendingPeerAdopt is the inverse of what this used to
// assert, and the inversion is the fix. A client request for a stale entry
// used to cancel any pending notice-driven adopt and start its own local
// rebuild instead, on the reasoning that the two were duplicate work.
//
// They are not interchangeable. The adopt installs the exact bytes the rest
// of the cluster is serving; a local rebuild produces this replica's own
// generation. Cancelling the adopt in favour of the rebuild is what let
// replicas drift apart under steady request traffic -- precisely the
// traffic pattern where it matters, since a busy layout gets a client
// request inside the adopt's jitter window nearly every time.
//
// So a request must serve the stale entry, leave the adopt alone, and start
// no rebuild of its own.
func TestGetLiveDefersToPendingPeerAdopt(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	cacheKey := "debian/trixie"
	stale := &liveEntry{expiry: time.Now().Add(-time.Minute)}
	s.liveCache[cacheKey] = stale

	// Simulate a live-updated notice having just arrived with its jitter
	// delay still pending.
	_, realCancel := context.WithCancel(context.Background())
	cancelled := false
	s.mu.Lock()
	s.pendingPeerAdopt[cacheKey] = func() { cancelled = true; realCancel() }
	s.mu.Unlock()

	entry, err := s.getLive(context.Background(), "debian", "trixie")
	if err != nil {
		t.Fatalf("getLive: %v", err)
	}
	if entry != stale {
		t.Fatal("expected the stale entry to be returned immediately while the adopt completes in the background")
	}

	s.mu.Lock()
	_, stillPending := s.pendingPeerAdopt[cacheKey]
	wait, building := s.liveBuilding[cacheKey]
	s.mu.Unlock()

	if cancelled {
		t.Error("client request cancelled the pending peer adopt; it must defer to it instead, or this replica rebuilds its own divergent generation")
	}
	if !stillPending {
		t.Error("pending peer adopt was dropped by a client request")
	}
	if building {
		t.Error("client request started a local rebuild alongside an in-flight peer adopt")
		<-wait
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
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files:  map[string][]byte{fileKey: content},
		hashes: map[string]string{fileKey: hash},
		expiry: time.Now().Add(time.Hour),
	}
	pubSrv := httptest.NewServer(publisher.Handler())
	defer pubSrv.Close()

	b := &serverValkeyBacking{peerHTTP: &http.Client{Timeout: 2 * time.Second}}
	notice := liveUpdatedMsg{
		Addrs:  []string{"127.0.0.1:1", pubSrv.Listener.Addr().String()}, // first is dead
		Files:  []string{fileKey},
		Hashes: map[string]string{fileKey: hash},
	}
	files, err := b.fetchLiveFiles(context.Background(), "debian", notice, nil)
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

	s.publishLiveUpdate("debian", "trixie", &liveEntry{
		files:  map[string][]byte{"k": []byte("v")},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	})

	select {
	case <-received:
		t.Error("publishLiveUpdate published a notice despite having no peer addresses to advertise")
	case <-time.After(500 * time.Millisecond):
		// expected: nothing published
	}
}

// TestPeerUserAgentTransportPrecedence proves peerUserAgentTransport's three
// -tier precedence: a live client's own User-Agent (passed through via
// upstream.WithUserAgent on the request context) beats the configured value,
// which beats the fixed fallback used when neither exists.
func TestPeerUserAgentTransportPrecedence(t *testing.T) {
	var gotUA string
	capture := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotUA = r.Header.Get("User-Agent")
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})

	newReq := func(ctx context.Context) *http.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example/", nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	cases := []struct {
		name       string
		ctx        context.Context
		configured string
		fallback   string
		want       string
	}{
		{
			name:       "client passthrough wins over configured and fallback",
			ctx:        upstream.WithUserAgent(context.Background(), "apt-client/1.0"),
			configured: "configured-ua",
			fallback:   "debproxy fallback",
			want:       "apt-client/1.0",
		},
		{
			name:       "configured wins when no client UA in context",
			ctx:        context.Background(),
			configured: "configured-ua",
			fallback:   "debproxy fallback",
			want:       "configured-ua",
		},
		{
			name:       "fallback used when neither client UA nor configured exist",
			ctx:        context.Background(),
			configured: "",
			fallback:   "debproxy fallback",
			want:       "debproxy fallback",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &peerUserAgentTransport{base: capture, configured: tc.configured, fallback: tc.fallback}
			if _, err := transport.RoundTrip(newReq(tc.ctx)); err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			if gotUA != tc.want {
				t.Errorf("User-Agent = %q, want %q", gotUA, tc.want)
			}
		})
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

// TestRebuildLiveSkipsWhenAnotherReplicaHoldsTheBuildLock is the direct
// regression test for the cross-replica rebuild race: when many replicas'
// entries for the same layout go stale around the same moment (the common
// case, since they were usually all built around the same original time),
// every one of them used to independently call generateLiveFiles for
// itself, and then every other replica's next stale check would also try
// to adopt the winner's result over HTTP at once -- a second thundering
// herd. Simulates two replicas sharing one Valkey (real container, not a
// mock -- this project's convention for anything lock/expiry-dependent) by
// pre-acquiring LiveBuildLock as replica A, then calling replica B's
// rebuildLive directly: B must skip its own rebuild entirely (no swap, no
// generateLiveFiles) rather than duplicate A's in-flight work.
func TestRebuildLiveSkipsWhenAnotherReplicaHoldsTheBuildLock(t *testing.T) {
	replicaA := newValkeyEnabledServer(t, ":19001")
	replicaB := newValkeyEnabledServer(t, ":19002")
	ctx := context.Background()

	lockA, ok, err := valkeycache.AcquireLock(ctx, replicaA.valkey.client, replicaA.valkey.keys.LiveBuildLock("debian", "trixie"), time.Minute)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if !ok {
		t.Fatal("expected replica A to acquire the previously-unheld lock")
	}
	t.Cleanup(func() { _ = lockA.Release(context.Background()) })

	cacheKey := "debian/trixie"
	original := &liveEntry{expiry: time.Now().Add(-time.Hour)} // stale, deliberately
	replicaB.liveCache[cacheKey] = original
	wait := make(chan struct{})
	replicaB.liveBuilding[cacheKey] = wait

	done := make(chan struct{})
	go func() {
		replicaB.rebuildLive("debian", "trixie", cacheKey, wait)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for rebuildLive to return -- it should skip immediately when the lock is held elsewhere")
	}

	replicaB.mu.Lock()
	entryAfter := replicaB.liveCache[cacheKey]
	_, stillBuilding := replicaB.liveBuilding[cacheKey]
	replicaB.mu.Unlock()

	if entryAfter != original {
		t.Fatal("replica B rebuilt/swapped its entry despite replica A holding the live build lock -- the redundant-rebuild race is not actually prevented")
	}
	if stillBuilding {
		t.Fatal("expected liveBuilding to be cleared even on the early-skip path, or a stuck flag would block all future rebuilds for this layout")
	}
}

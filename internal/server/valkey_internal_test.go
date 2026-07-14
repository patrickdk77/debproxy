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
	"github.com/debproxy/debproxy/internal/upstream"
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
	stop := s.EnableValkey(context.Background(), client, listenAddr, "")
	t.Cleanup(stop)
	return s
}

// TestHandleLiveUpdatedMessageProactivelyRebuildsMatchingEntry proves the
// actual current behavior: receiving a live-updated notice doesn't just mark
// the matching entry stale and wait for a client request to notice (see
// getLive) -- after the jitter delay, it proactively rebuilds/adopts right
// away on its own, replacing the entry outright. Detected via pointer
// identity (swapLiveEntry always installs a new *liveEntry), since the
// invalidated state is only transient now -- a real rebuild follows
// immediately, so polling for a zero expiry is racy against that replacement.
func TestHandleLiveUpdatedMessageProactivelyRebuildsMatchingEntry(t *testing.T) {
	// The proactive adopt is jittered (see liveUpdateInvalidateJitter) --
	// shrink it so this test doesn't have to wait out the full production
	// window.
	orig := liveUpdateInvalidateJitter
	liveUpdateInvalidateJitter = time.Millisecond
	t.Cleanup(func() { liveUpdateInvalidateJitter = orig })

	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)

	future := time.Now().Add(time.Hour)
	originalTrixie := &liveEntry{expiry: future}
	originalNoble := &liveEntry{expiry: future}
	s.liveCache["debian/trixie"] = originalTrixie
	s.liveCache["ubuntu/noble"] = originalNoble

	msg, err := json.Marshal(liveUpdatedMsg{OS: "debian", Codename: "trixie"})
	if err != nil {
		t.Fatal(err)
	}
	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		replaced := s.liveCache["debian/trixie"] != originalTrixie
		s.mu.Unlock()
		if replaced {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for debian/trixie entry to be proactively rebuilt")
		}
		time.Sleep(time.Millisecond)
	}

	s.mu.Lock()
	untouched := s.liveCache["ubuntu/noble"]
	s.mu.Unlock()
	if untouched != originalNoble {
		t.Fatal("expected unrelated ubuntu/noble entry to be left untouched")
	}
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

// TestGetLiveCancelsPendingPeerAdoptOnClientRequest proves the other half of
// the design: a client request for a stale entry must cancel any still-
// pending notice-driven proactive adopt for the same cacheKey (see
// handleLiveUpdatedMessage) rather than let both fire and duplicate the same
// rebuild -- the client's own request already triggers it immediately.
func TestGetLiveCancelsPendingPeerAdoptOnClientRequest(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	cacheKey := "debian/trixie"
	s.liveCache[cacheKey] = &liveEntry{expiry: time.Now().Add(-time.Minute)} // stale

	// Simulate a live-updated notice having just arrived with its jitter
	// delay still pending (long enough that it won't fire during this test).
	_, realCancel := context.WithCancel(context.Background())
	called := false
	wrappedCancel := func() { called = true; realCancel() }
	s.mu.Lock()
	s.pendingPeerAdopt[cacheKey] = wrappedCancel
	s.mu.Unlock()

	entry, err := s.getLive(context.Background(), "debian", "trixie")
	if err != nil {
		t.Fatalf("getLive: %v", err)
	}
	if entry == nil {
		t.Fatal("expected the stale entry to still be returned immediately")
	}

	if !called {
		t.Error("expected the pending peer-adopt timer's cancel func to be called")
	}
	s.mu.Lock()
	_, stillPending := s.pendingPeerAdopt[cacheKey]
	wait, building := s.liveBuilding[cacheKey]
	s.mu.Unlock()
	if stillPending {
		t.Error("expected the pending peer-adopt entry to be removed once a client request took over")
	}

	// Let the background rebuild this request triggered finish so it
	// doesn't leak past the test.
	if building {
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

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/logwriter"
)

// knownServer returns a Server that recognizes exactly one layout triple,
// with the maps a request path touches already allocated.
func knownServer(store interface{}) *Server {
	s := &Server{
		liveCache:        map[string]*liveEntry{},
		liveBuilding:     map[string]chan struct{}{},
		pendingPeerAdopt: map[string]context.CancelFunc{},
		validOSCodename:  map[string]bool{"debian/trixie": true},
		validTriple:      map[string]bool{"debian/trixie/debian-main": true},
	}
	if st, ok := store.(interface {
		Exists(context.Context, string) (bool, error)
	}); ok {
		_ = st
	}
	return s
}

// TestLivePoolRejectsMismatchedOSSegment is the regression test for the
// unvalidated os segment: the URL's os is checked against known layouts,
// but the pool path carries its own os segment and resolvePoolPackage
// built a live index for whatever it said. A junk segment must 404 at the
// router and must leave no trace in the live cache.
func TestLivePoolRejectsMismatchedOSSegment(t *testing.T) {
	store := &failingStore{}
	s := knownServer(store)
	s.store = store
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/pool/junk/trixie/debian-main/x/y/z_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("mismatched os segment: status %d, want 404", resp.StatusCode)
	}
	if store.reads != 0 {
		t.Errorf("storage was consulted %d times for a rejected path", store.reads)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.liveCache) != 0 || len(s.liveBuilding) != 0 {
		t.Errorf("junk layout left state behind: cache=%d building=%d",
			len(s.liveCache), len(s.liveBuilding))
	}
}

// TestLivePoolMatchingOSSegmentProceeds proves the guard is not simply
// rejecting everything: a consistent path gets past it to storage.
func TestLivePoolMatchingOSSegmentProceeds(t *testing.T) {
	store := &failingStore{}
	s := knownServer(store)
	s.store = store
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/x/y/z_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("consistent path was rejected by the os guard")
	}
	if store.reads == 0 {
		t.Fatal("consistent path never reached storage")
	}
}

func TestLiveSrcRejectsMismatchedOSSegment(t *testing.T) {
	store := &failingStore{}
	s := knownServer(store)
	s.store = store
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/src/junk/trixie/debian-main/x/y/z.dsc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if store.reads != 0 {
		t.Errorf("storage consulted %d times", store.reads)
	}
}

// TestResolvePoolPackageRefusesUnknownLayout is the defense-in-depth half:
// even a caller that bypasses the router must not get a live build for an
// os/codename no layout defines.
func TestResolvePoolPackageRefusesUnknownLayout(t *testing.T) {
	s := knownServer(nil)
	_, _, _, err := s.resolvePoolPackage(context.Background(),
		"pool/junk/trixie/debian-main/x/y/z.deb")
	if err == nil {
		t.Fatal("unknown layout accepted")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.liveBuilding) != 0 || len(s.liveCache) != 0 {
		t.Error("unknown layout left live state behind")
	}
}

// --- negative cache and single-flight for upstream re-resolve ---

func TestRecentMissFalseWhenNeverRecorded(t *testing.T) {
	s := &Server{}
	if s.recentMiss("pool/x") {
		t.Fatal("miss reported for a path never seen")
	}
}

func TestFinishResolveWithErrorRecordsMiss(t *testing.T) {
	s := &Server{}
	fl, leader := s.beginResolve("pool/x")
	if !leader {
		t.Fatal("first caller must lead")
	}
	s.finishResolve("pool/x", fl, avail.Pkg{}, errors.New("nope"))
	if !s.recentMiss("pool/x") {
		t.Fatal("failed resolve did not record a miss")
	}
	if s.recentMiss("pool/other") {
		t.Fatal("miss leaked to an unrelated path")
	}
}

func TestFinishResolveWithSuccessDoesNotRecordMiss(t *testing.T) {
	s := &Server{}
	fl, _ := s.beginResolve("pool/x")
	s.finishResolve("pool/x", fl, avail.Pkg{Name: "hello"}, nil)
	if s.recentMiss("pool/x") {
		t.Fatal("successful resolve recorded as a miss")
	}
}

func TestRecentMissExpires(t *testing.T) {
	s := &Server{resolveMiss: map[string]time.Time{
		"pool/x": time.Now().Add(-time.Second),
	}}
	if s.recentMiss("pool/x") {
		t.Fatal("expired miss still honored")
	}
	if _, still := s.resolveMiss["pool/x"]; still {
		t.Fatal("expired miss not evicted")
	}
}

// TestBeginResolveElectsExactlyOneLeader is the single-flight guarantee:
// however many requests race for the same path, one does the fetch and
// the rest wait on it and get its answer.
func TestBeginResolveElectsExactlyOneLeader(t *testing.T) {
	s := &Server{}
	const n = 64
	var wg sync.WaitGroup
	var leaders int32
	var mu sync.Mutex
	results := make([]*resolveFlight, 0, n)
	start := make(chan struct{})
	// The leader holds its flight open until every goroutine has joined,
	// so all n of them race the same in-flight entry. Without this
	// barrier a leader that finishes first correctly lets the next caller
	// start a fresh flight, which is not what this test is checking.
	var joined sync.WaitGroup
	joined.Add(n)
	allJoined := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			fl, leader := s.beginResolve("pool/x")
			mu.Lock()
			if leader {
				leaders++
			}
			results = append(results, fl)
			mu.Unlock()
			joined.Done()
			if leader {
				<-allJoined
				s.finishResolve("pool/x", fl, avail.Pkg{Name: "hello"}, nil)
			}
		}()
	}
	close(start)
	joined.Wait()
	close(allJoined)
	wg.Wait()

	if leaders != 1 {
		t.Fatalf("%d leaders, want exactly 1", leaders)
	}
	for _, fl := range results {
		select {
		case <-fl.done:
		default:
			t.Fatal("a follower's flight was never completed")
		}
		if fl.err != nil || fl.pkg.Name != "hello" {
			t.Fatalf("follower got %+v / %v", fl.pkg, fl.err)
		}
	}
	s.resolveMu.Lock()
	defer s.resolveMu.Unlock()
	if len(s.resolveInflight) != 0 {
		t.Error("in-flight map not cleared after finish")
	}
}

func TestBeginResolveDistinctPathsDoNotShare(t *testing.T) {
	s := &Server{}
	_, l1 := s.beginResolve("pool/a")
	_, l2 := s.beginResolve("pool/b")
	if !l1 || !l2 {
		t.Fatal("distinct paths shared a flight")
	}
}

// --- cold-start build must clear its marker on panic ---

// TestColdStartBuildClearsMarkerOnPanic drives a panic through the
// cold-start build (a nil IndexCache makes TryLock dereference nil) and
// checks that the building marker is gone afterwards. Before the deferred
// cleanup, every later request for the layout parked on a channel nobody
// would close.
func TestColdStartBuildClearsMarkerOnPanic(t *testing.T) {
	s := knownServer(nil)
	s.indexCache = nil

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected the build to panic on a nil IndexCache")
			}
		}()
		_, _ = s.getLive(context.Background(), "debian", "trixie")
	}()

	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, still := s.liveBuilding["debian/trixie"]; still {
		select {
		case <-ch:
			t.Fatal("marker left set after panic (channel closed but not deleted)")
		default:
			t.Fatal("marker left set after panic; later requests would hang")
		}
	}
}

// --- clientGone on the sites the earlier pass missed ---

func TestServePoolExistsClientCancelIsNotAnError(t *testing.T) {
	store := &cancelStore{}
	s := knownServer(store)
	s.store = store

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/live/debian/pool/debian/trixie/debian-main/x/y/z.deb", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.servePool(rec, req, "pool/debian/trixie/debian-main/x/y/z.deb", true, "debian", "trixie", "debian-main")

	if store.calls == 0 {
		t.Fatal("storage never consulted; test proves nothing")
	}
	if rec.Code == http.StatusInternalServerError {
		t.Errorf("client cancellation on Exists reported as 500")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("wrote %d bytes to a gone client", rec.Body.Len())
	}
}

func TestServeSrcExistsClientCancelIsNotAnError(t *testing.T) {
	store := &cancelStore{}
	s := knownServer(store)
	s.store = store

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/live/debian/src/debian/trixie/debian-main/x/y/z.dsc", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.serveSrc(rec, req, "debian", "trixie", "src/debian/trixie/debian-main/x/y/z.dsc")

	if store.calls == 0 {
		t.Fatal("storage never consulted")
	}
	if rec.Code == http.StatusInternalServerError {
		t.Errorf("client cancellation on src Exists reported as 500")
	}
}

// --- access log must not let a forwarded header forge fields ---

type syncLogSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestAccessLogSanitizesForwardedClientIP(t *testing.T) {
	var out syncLogSink
	prev := accessLog
	accessLog = logwriter.New(&out, 0)
	defer func() { accessLog = prev }()

	h := logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	// Driven through ServeHTTP directly: Go's client refuses to send a
	// header containing a newline, but a raw socket does not, and the
	// server side is what has to cope with it.
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4\" 200 \"\n9.9.9.9 - - [forged]")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	io.Copy(io.Discard, rec.Body)
	_ = accessLog.Close()

	got := out.String()
	if strings.Contains(got, "[forged]") && strings.Contains(got, "\n9.9.9.9") {
		t.Errorf("forwarded header forged a log line: %q", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("expected exactly one log line, got %d: %q", strings.Count(got, "\n"), got)
	}
	if !strings.Contains(got, "1.2.3.4") {
		t.Errorf("legitimate part of the client ip was dropped: %q", got)
	}
}

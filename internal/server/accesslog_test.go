package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/logwriter"
)

// syncWriter lets the writer goroutine append while the test reads.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// stalledSink blocks every Write until release is closed, standing in
// for a container log pipe whose collector has stopped draining.
type stalledSink struct{ release chan struct{} }

func (s *stalledSink) Write(p []byte) (int, error) {
	<-s.release
	return len(p), nil
}

// swapAccessLog points the access log at a stalled sink for the
// duration of one test and restores the original afterwards.
func swapAccessLog(t *testing.T, queue int) *stalledSink {
	t.Helper()
	sink := &stalledSink{release: make(chan struct{})}
	prev := accessLog
	accessLog = logwriter.New(sink, queue)
	t.Cleanup(func() {
		close(sink.release)
		_ = accessLog.Close()
		accessLog = prev
	})
	return sink
}

// TestRequestsSucceedWhileAccessLogStalled is the regression test for
// the production failure this guards against. The access log line is
// written after the wrapped handler runs but before the middleware
// returns, and net/http only flushes a response to the socket once the
// whole chain has returned. So a blocking write to a full container
// log pipe used to strand an already-written response: the connection
// was accepted and then never answered, which is what health probes
// reported as a timeout before restarting the container.
//
// Every request must still be answered here, not just /healthz --
// apt clients go through the identical middleware.
func TestRequestsSucceedWhileAccessLogStalled(t *testing.T) {
	swapAccessLog(t, 2)

	h := logging(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("payload"))
		}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	// More requests than the queue depth, so the writer is
	// genuinely saturated and dropping rather than absorbing them.
	for i := 0; i < 50; i++ {
		resp, err := client.Get(srv.URL + "/live/dists/trixie/InRelease")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d body: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		if string(body) != "payload" {
			t.Fatalf("request %d: body %q", i, string(body))
		}
	}
}

// TestHealthzSucceedsWhileAccessLogStalled covers the probe path
// specifically, through the full Handler() chain rather than the
// logging middleware alone, since that chain is what the kubelet hits.
func TestHealthzSucceedsWhileAccessLogStalled(t *testing.T) {
	swapAccessLog(t, 1)

	s := &Server{}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	for i := 0; i < 20; i++ {
		resp, err := client.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("probe %d body: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("probe %d: status %d", i, resp.StatusCode)
		}
		if string(body) != "ok" {
			t.Fatalf("probe %d: body %q", i, string(body))
		}
	}
}

// TestAccessLogLinesReachSinkOnceDrained confirms the fix did not
// silently turn logging into a no-op: with a sink that accepts writes,
// the request line still comes through.
func TestAccessLogLinesReachSinkOnceDrained(t *testing.T) {
	var out syncWriter
	prev := accessLog
	accessLog = logwriter.New(&out, 0)
	defer func() { accessLog = prev }()

	h := logging(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/pool/main/h/hello.deb")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	_ = accessLog.Close()

	got := out.String()
	if !contains(got, "/live/pool/main/h/hello.deb") {
		t.Errorf("access log missing request path: %q", got)
	}
	if !contains(got, "200") {
		t.Errorf("access log missing status: %q", got)
	}
}

// TestStalledSinkActuallyBlocks keeps the two tests above honest. If
// the sink ever stopped blocking, they would pass no matter how the
// middleware wrote its log line, and would quietly stop guarding
// anything. A synchronous write -- what the middleware used to do --
// must still hang here.
func TestStalledSinkActuallyBlocks(t *testing.T) {
	sink := &stalledSink{release: make(chan struct{})}
	defer close(sink.release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sink.Write([]byte("x"))
	}()
	select {
	case <-done:
		t.Fatal("stalled sink did not block; stall tests prove nothing")
	case <-time.After(200 * time.Millisecond):
	}
}

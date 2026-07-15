package server

import (
	"net/http/httptest"
	"testing"
)

// trackFlushResponseWriter wraps httptest.NewRecorder (which doesn't itself
// implement http.Flusher) so it can report whether Flush reached it.
type trackFlushResponseWriter struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (w *trackFlushResponseWriter) Flush() { w.flushed = true }

// TestStatusWriterAndCompressWriterForwardFlush is the direct regression
// test for a real bug found in this session: wrapping http.ResponseWriter in
// a struct that embeds it (statusWriter for every request via logging/
// metricsMiddleware, compressWriter when a client requests compression)
// silently breaks http.Flusher, since Go only promotes the methods declared
// on the embedded interface's own type (Header/Write/WriteHeader), never an
// additional optional interface the concrete value underneath separately
// satisfies. Without Flush forwarding through every layer, streaming pool
// pull-through (internal/ingest's digestVerifyingReader, which calls Flush
// after every tee'd write) silently degrades back to fully-buffered
// responses -- bytes sit in Go's internal per-response buffer and never
// reach the client until it accumulates enough to auto-flush, defeating the
// entire point of streaming. This was caught by
// TestPoolPullThroughStreamsBeforeUpstreamFinishes (internal/server/e2e_test.go)
// hanging/timing out; this test pins the fix at the unit level too.
func TestStatusWriterAndCompressWriterForwardFlush(t *testing.T) {
	t.Run("statusWriter", func(t *testing.T) {
		inner := &trackFlushResponseWriter{ResponseRecorder: httptest.NewRecorder()}
		sw := &statusWriter{ResponseWriter: inner, status: 200}
		sw.Flush()
		if !inner.flushed {
			t.Error("statusWriter.Flush() did not reach the underlying ResponseWriter")
		}
	})
	t.Run("compressWriter no active compressor", func(t *testing.T) {
		inner := &trackFlushResponseWriter{ResponseRecorder: httptest.NewRecorder()}
		cw := &compressWriter{ResponseWriter: inner}
		cw.Flush()
		if !inner.flushed {
			t.Error("compressWriter.Flush() did not reach the underlying ResponseWriter")
		}
	})
	t.Run("compressWriter wrapping statusWriter", func(t *testing.T) {
		// Mirrors the real middleware chain order (compress wraps whatever
		// logging/metricsMiddleware already wrapped): Flush must cascade
		// through both layers, not just the outermost one.
		inner := &trackFlushResponseWriter{ResponseRecorder: httptest.NewRecorder()}
		sw := &statusWriter{ResponseWriter: inner, status: 200}
		cw := &compressWriter{ResponseWriter: sw}
		cw.Flush()
		if !inner.flushed {
			t.Error("Flush did not cascade through statusWriter to the real ResponseWriter")
		}
	})
}

func TestSanitizeLogFieldStripsInjection(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`normal-user-agent/1.0`, `normal-user-agent/1.0`},
		{`evil" 200 999999 "-`, `evil 200 999999 -`},
		{"has\nnewline", "hasnewline"},
		{"has\rcarriage", "hascarriage"},
		{"has\x00null", "hasnull"},
	}
	for _, c := range cases {
		if got := sanitizeLogField(c.in); got != c.want {
			t.Errorf("sanitizeLogField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

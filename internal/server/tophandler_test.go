package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/logwriter"
)

// The admin API was mounted beside Handler() rather than inside it, so
// every /api/ request bypassed the access log: the e2e run's logins,
// lockout and snapshot creation left no request line at all.
func TestTopHandlerLogsAPIRequests(t *testing.T) {
	var out syncLogSink
	prev := accessLog
	accessLog = logwriter.New(&out, 0)
	defer func() { accessLog = prev }()

	reached := false
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusForbidden)
	})
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	h := s.TopHandler(api)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	req.RemoteAddr = "10.1.2.3:4000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	io.Copy(io.Discard, rec.Body)
	_ = accessLog.Close()

	if !reached {
		t.Fatal("/api/ request did not reach the API handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want the API handler's 403", rec.Code)
	}
	got := out.String()
	if !strings.Contains(got, `"POST /api/v1/snapshot HTTP/1.1" 403`) || !strings.Contains(got, "10.1.2.3") {
		t.Fatalf("no access-log line for the API request:\n%s", got)
	}
}

// Everything else still goes to the web handler: /healthz must answer
// without touching the API.
func TestTopHandlerRoutesWebPaths(t *testing.T) {
	var out syncLogSink
	prev := accessLog
	accessLog = logwriter.New(&out, 0)
	defer func() { accessLog = prev }()

	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("web path %s reached the API handler", r.URL.Path)
	})
	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	h := s.TopHandler(api)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	_ = accessLog.Close()
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status %d", rec.Code)
	}
	if !strings.Contains(out.String(), `"GET /healthz HTTP/1.1" 200`) {
		t.Fatalf("web request not logged:\n%s", out.String())
	}
}

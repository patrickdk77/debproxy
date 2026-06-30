package upstream

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRetryOn5xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rt := &retryTransport{
		base:        http.DefaultTransport.(*http.Transport).Clone(),
		maxAttempts: 4,
		retryDelay:  0,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("unexpected body: %q", body)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", calls.Load())
	}
}

func TestNo5xxRetryWhenMaxAttemptsExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	rt := &retryTransport{
		base:        http.DefaultTransport.(*http.Transport).Clone(),
		maxAttempts: 3,
		retryDelay:  0,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 3 attempts, still 502  --  return it rather than error.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", calls.Load())
	}
}

func TestNoRetryFor4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rt := &retryTransport{
		base:        http.DefaultTransport.(*http.Transport).Clone(),
		maxAttempts: 3,
		retryDelay:  0,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly 1 call for 4xx, got %d", calls.Load())
	}
}

func TestNoRetryForRequestWithBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rt := &retryTransport{
		base:        http.DefaultTransport.(*http.Transport).Clone(),
		maxAttempts: 4,
		retryDelay:  0,
	}
	client := &http.Client{Transport: rt}

	// POST with a body  --  must not retry even on 5xx.
	resp, err := client.Post(srv.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if calls.Load() != 1 {
		t.Fatalf("expected 1 call for request with body, got %d", calls.Load())
	}
}

func TestContextCancellationStopsRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	rt := &retryTransport{
		base:        http.DefaultTransport.(*http.Transport).Clone(),
		maxAttempts: 10,
		retryDelay:  0,
	}
	client := &http.Client{Transport: rt}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestNewHTTPClientReturnsWorkingClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()

	client := NewHTTPClient("")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Fatalf("unexpected body: %q", body)
	}
}

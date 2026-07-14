package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type contextKey int

const (
	userAgentKey contextKey = iota
	clientWaitingKey
)

// WithUserAgent stores ua in ctx so that upstream fetches made with that
// context will use it as the outgoing User-Agent (when no global UA is configured).
func WithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, userAgentKey, ua)
}

// WithClientWaiting marks ctx as one where a real client HTTP request is
// synchronously blocked on the result -- currently only true for a /live
// cold start with nothing yet cached for that os/codename. See
// fastFallbackTimeout's doc comment (fetch.go) for why this distinction
// matters: every other caller of FetchIndex/FetchSources -- the periodic
// refresher, a stale live entry's background rebuild, an async admin job --
// has no client waiting on it at all, and should always spend the full
// retry budget chasing a correct answer rather than degrading early to a
// stale fallback just because one happens to exist.
func WithClientWaiting(ctx context.Context) context.Context {
	return context.WithValue(ctx, clientWaitingKey, true)
}

// clientIsWaiting reports whether ctx was marked via WithClientWaiting.
func clientIsWaiting(ctx context.Context) bool {
	v, _ := ctx.Value(clientWaitingKey).(bool)
	return v
}

// UserAgentFromContext returns the User-Agent stored by WithUserAgent, if
// any -- used by callers outside this package (e.g. the server's
// peer-to-peer live-cache fetch client) that need the same passthrough value
// without going through NewHTTPClient's own configured>context precedence.
func UserAgentFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(userAgentKey).(string)
	return v, ok
}

// NewHTTPClient returns an *http.Client tuned for fetching from Debian mirror
// upstreams:
//   - 10 s connect and TLS handshake timeout
//   - 30 s response-header timeout (body read is unbounded; use a context)
//   - up to 3 retries on transient failures (network errors, 5xx), with idle
//     connections closed before each retry so the dialer re-resolves DNS and
//     may land on a different mirror IP
//
// userAgent is sent as the User-Agent header on every outgoing request. When
// empty, the User-Agent stored in the request context by WithUserAgent is used
// instead (allowing the server to pass through the apt client's UA).
func NewHTTPClient(userAgent string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	base := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true, // we request pre-compressed files by URL; no auto Accept-Encoding/decompression
	}
	retry := &retryTransport{base: base, maxAttempts: 4, retryDelay: time.Second}
	return &http.Client{
		Transport: &userAgentTransport{base: retry, configured: userAgent},
	}
}

// userAgentTransport sets the User-Agent header on every outgoing request.
// Priority: configured (static) > context value (request passthrough) > unset.
type userAgentTransport struct {
	base       http.RoundTripper
	configured string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ua := t.configured
	if ua == "" {
		if v, ok := req.Context().Value(userAgentKey).(string); ok {
			ua = v
		}
	}
	if ua != "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", ua)
	}
	return t.base.RoundTrip(req)
}

// retryTransport retries idempotent (no-body) requests on network errors and
// 5xx responses. Before each retry it calls CloseIdleConnections so the next
// dial opens a fresh TCP connection, re-resolves DNS, and may connect to a
// different IP if the upstream has multiple A records.
type retryTransport struct {
	base        *http.Transport
	maxAttempts int
	retryDelay  time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only retry requests without a body  --  we cannot replay a consumed stream.
	if req.Body != nil && req.Body != http.NoBody {
		return t.base.RoundTrip(req)
	}

	var lastErr error
	for attempt := 0; attempt < t.maxAttempts; attempt++ {
		if attempt > 0 {
			// Fresh connection forces a new DNS lookup on the next dial.
			t.base.CloseIdleConnections()
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(t.retryDelay * time.Duration(attempt)):
			}
		}

		resp, err := t.base.RoundTrip(req)
		if err != nil {
			if !isRetryableErr(err) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 && attempt < t.maxAttempts-1 {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: upstream returned %d", req.URL.Host, resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// isRetryableErr returns true for transient errors. Context cancellation and
// deadline exceeded are not retried  --  the caller has already given up.
func isRetryableErr(err error) bool {
	return err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

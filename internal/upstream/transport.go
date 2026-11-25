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
	networkKey
	s3OptionsKey
)

// withNetwork stores network ("ipv4"/"ipv6") in ctx so upstream fetches made
// with that context dial over that IP family, taking precedence over
// NewHTTPClient's own static default -- see the dial closure in NewHTTPClient
// for why a per-upstream override needs to win over the global default, the
// opposite precedence from userAgentTransport's configured>context (an
// operator's specific-mirror override should beat the general default, not
// the other way around).
func withNetwork(ctx context.Context, network string) context.Context {
	return context.WithValue(ctx, networkKey, network)
}

func networkFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(networkKey).(string)
	return v, ok
}

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
//
// network is the default IP family forced for every dial: "ipv4", "ipv6", or
// "" for the default dual-stack behavior (Happy Eyeballs races both, using
// whichever connects first, per net.Dialer's own FallbackDelay). Set this
// when one family is broken in a way a connect-time race doesn't reliably
// protect against -- e.g. a network that silently black-holes one family
// (hangs rather than failing fast) somewhere before or during the connect
// attempt, not just a family that actively refuses connections quickly. A
// per-upstream override carried in the request context (see withNetwork,
// set by Fetcher for an UpstreamSource with its own Network value) takes
// precedence over this default for that specific request.
//
// An s3:// URL is served by s3Transport through the same client, with the
// same dial rules and the same retry policy; see s3.go.
func NewHTTPClient(userAgent, network string) *http.Client {
	dialContext := newDialContext(network)
	base := newBaseTransport(dialContext)
	base.RegisterProtocol("s3", newS3Transport(dialContext))
	retry := &retryTransport{base: base, maxAttempts: 4, retryDelay: time.Second}
	return &http.Client{
		Transport: &userAgentTransport{base: retry, configured: userAgent},
	}
}

type dialFunc func(ctx context.Context, netw, addr string) (net.Conn, error)

// newDialContext returns the dialer every upstream connection goes
// through: network is the process-wide IP family default, and a value
// stored in ctx by withNetwork wins over it for that request.
func newDialContext(network string) dialFunc {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		forced := network
		if v, ok := networkFromContext(ctx); ok && v != "" {
			forced = v
		}
		switch forced {
		case "ipv4":
			return dialer.DialContext(ctx, "tcp4", addr)
		case "ipv6":
			return dialer.DialContext(ctx, "tcp6", addr)
		default:
			return dialer.DialContext(ctx, netw, addr)
		}
	}
}

// newBaseTransport returns the http.Transport with the timeouts and pool
// sizes upstream fetches use; the S3 SDK's own connections use one too.
func newBaseTransport(dialContext dialFunc) *http.Transport {
	return &http.Transport{
		DialContext:           dialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true, // we request pre-compressed files by URL; no auto Accept-Encoding/decompression
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
// Neither is a permanentError, which marks a failure a retry cannot change.
func isRetryableErr(err error) bool {
	var perm permanentError
	return err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) &&
		!errors.As(err, &perm)
}

// permanentError wraps an error that retrying cannot fix, such as a
// misconfigured upstream, so retryTransport returns it at once.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

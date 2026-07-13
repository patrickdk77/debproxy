package valkeycache

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Lock operations are retried a few times on transient connection errors.
// valkey-go multiplexes every concurrent command over a small fixed set of
// persistent connections and only auto-retries *read-only* commands on a
// network error -- a lock's SET NX (and the token-guarded renew/release Lua
// scripts) are writes, so a single connection reset (e.g. an in-cluster
// conntrack/CNI flow eviction) surfaces to every command riding that
// connection at once, unretried. These retries absorb that: all three lock
// ops are safe to re-run, because a retried acquire that actually succeeded
// server-side just returns "not held" on the retry, which callers already
// treat as "someone else holds it" and fail open.
const (
	lockOpMaxAttempts  = 3
	lockOpRetryBackoff = 50 * time.Millisecond
)

// withRetry runs fn up to lockOpMaxAttempts times, retrying only transient
// connection errors. A nil/held result, a context error, or a Valkey protocol
// error is returned immediately (isRetryableConnErr screens those out).
func withRetry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < lockOpMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(lockOpRetryBackoff * time.Duration(attempt)):
			}
		}
		if err = fn(); err == nil || !isRetryableConnErr(err) {
			return err
		}
	}
	return err
}

// isRetryableConnErr reports whether err is a transient transport failure
// worth retrying, as opposed to a valid result (Valkey nil), a caller
// cancellation, or a deterministic Valkey protocol error (which a retry can't
// fix).
func isRetryableConnErr(err error) bool {
	if err == nil {
		return false
	}
	// A nil reply (SET NX found the key already set) is a valid outcome, and a
	// caller-driven cancellation/deadline must not be masked by retries.
	if valkey.IsValkeyNil(err) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Transport-level failures: broken/closed connection, reset, EOF mid-read.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, valkey.ErrClosing) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

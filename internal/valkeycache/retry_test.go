package valkeycache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/valkey-io/valkey-go"
)

func TestIsRetryableConnErr(t *testing.T) {
	// The two errors actually observed in production, plus their wrapped forms.
	connReset := &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET}

	retryable := []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		fmt.Errorf("read: %w", io.ErrUnexpectedEOF),
		net.ErrClosed,
		valkey.ErrClosing,
		connReset,
		fmt.Errorf("acquire lock x: %w", connReset),
		syscall.ECONNRESET,
		syscall.EPIPE,
	}
	for _, err := range retryable {
		if !isRetryableConnErr(err) {
			t.Errorf("isRetryableConnErr(%v) = false, want true", err)
		}
	}

	notRetryable := []error{
		nil,
		context.Canceled,
		context.DeadlineExceeded,
		fmt.Errorf("op: %w", context.DeadlineExceeded),
		errors.New("WRONGTYPE Operation against a key holding the wrong kind of value"),
	}
	for _, err := range notRetryable {
		if isRetryableConnErr(err) {
			t.Errorf("isRetryableConnErr(%v) = true, want false", err)
		}
	}
}

func TestWithRetry_RetriesTransientThenSucceeds(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		if calls < 2 {
			return io.ErrUnexpectedEOF
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withRetry: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (one transient failure then success)", calls)
	}
}

func TestWithRetry_DoesNotRetryNonTransient(t *testing.T) {
	calls := 0
	sentinel := errors.New("WRONGTYPE")
	err := withRetry(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("withRetry err = %v, want the sentinel", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (non-transient errors are not retried)", calls)
	}
}

func TestWithRetry_ExhaustsAndReturnsLastErr(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), func() error {
		calls++
		return io.ErrUnexpectedEOF
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("withRetry err = %v, want io.ErrUnexpectedEOF", err)
	}
	if calls != lockOpMaxAttempts {
		t.Errorf("calls = %d, want %d", calls, lockOpMaxAttempts)
	}
}

func TestWithRetry_StopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := withRetry(ctx, func() error {
		calls++
		return io.ErrUnexpectedEOF
	})
	// First attempt runs; the backoff before attempt 2 observes the canceled ctx.
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (canceled ctx stops further retries)", calls)
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want context.Canceled or the last op error", err)
	}
}

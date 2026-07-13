package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/api"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

func TestOpLock_LocalAcquireRelease(t *testing.T) {
	lock := api.NewOpLock(nil, valkeycache.Keys{})
	ctx := context.Background()

	held, err := lock.Acquire(ctx, time.Minute, time.Second)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if held == nil {
		t.Fatal("expected to acquire an uncontended local lock")
	}
	if err := held.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestOpLock_LocalMutualExclusion(t *testing.T) {
	lock := api.NewOpLock(nil, valkeycache.Keys{})
	ctx := context.Background()

	held, err := lock.Acquire(ctx, time.Minute, time.Second)
	if err != nil || held == nil {
		t.Fatalf("first Acquire failed: err=%v held=%v", err, held)
	}

	// A second acquire while the first is still held should time out
	// (nil, nil) rather than block forever or spuriously succeed.
	second, err := lock.Acquire(ctx, time.Minute, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	if second != nil {
		t.Fatal("expected the second Acquire to report the lock as busy")
	}

	if err := held.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Now that it's released, a third acquire should succeed.
	third, err := lock.Acquire(ctx, time.Minute, time.Second)
	if err != nil {
		t.Fatalf("third Acquire: %v", err)
	}
	if third == nil {
		t.Fatal("expected the third Acquire to succeed after release")
	}
}

func TestOpLock_AcquireRespectsContextCancellation(t *testing.T) {
	lock := api.NewOpLock(nil, valkeycache.Keys{})
	ctx := context.Background()
	held, err := lock.Acquire(ctx, time.Minute, time.Second)
	if err != nil || held == nil {
		t.Fatalf("first Acquire failed: err=%v held=%v", err, held)
	}
	defer held.Release(ctx)

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lock.Acquire(cancelCtx, time.Minute, 0); err == nil {
		t.Fatal("expected Acquire to return an error for an already-canceled context")
	}
}

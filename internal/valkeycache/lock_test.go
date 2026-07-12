package valkeycache

import (
	"context"
	"testing"
	"time"
)

func TestAcquireLockSucceedsWhenFree(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()

	lock, ok, err := AcquireLock(ctx, v, "lock:test:free", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if !ok || lock == nil {
		t.Fatalf("expected lock acquired, got ok=%v lock=%v", ok, lock)
	}
}

func TestAcquireLockFailsWhenAlreadyHeld(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()

	if _, ok, err := AcquireLock(ctx, v, "lock:test:held", time.Minute); err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}

	lock, ok, err := AcquireLock(ctx, v, "lock:test:held", time.Minute)
	if err != nil {
		t.Fatalf("second AcquireLock returned error: %v", err)
	}
	if ok || lock != nil {
		t.Fatalf("expected second acquire to fail cleanly, got ok=%v lock=%v", ok, lock)
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()

	lock, ok, err := AcquireLock(ctx, v, "lock:test:release", time.Minute)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}

	_, ok, err = AcquireLock(ctx, v, "lock:test:release", time.Minute)
	if err != nil {
		t.Fatalf("reacquire: %v", err)
	}
	if !ok {
		t.Fatal("expected reacquire to succeed after release")
	}
}

func TestReleaseDoesNotDeleteAnotherHoldersLock(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()
	key := "lock:test:stolen"

	first, ok, err := AcquireLock(ctx, v, key, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	time.Sleep(600 * time.Millisecond) // let it expire

	second, ok, err := AcquireLock(ctx, v, key, time.Minute)
	if err != nil || !ok {
		t.Fatalf("second acquire after expiry: ok=%v err=%v", ok, err)
	}

	// first's token no longer matches what's stored; its Release must be a no-op.
	if err := first.Release(ctx); err != nil {
		t.Fatalf("stale Release returned error: %v", err)
	}

	// second must still hold the lock: a fresh acquire attempt must fail.
	_, ok, err = AcquireLock(ctx, v, key, time.Minute)
	if err != nil {
		t.Fatalf("acquire after stale release: %v", err)
	}
	if ok {
		t.Fatal("stale Release incorrectly deleted the second holder's lock")
	}
	_ = second
}

func TestRenewExtendsTTLWhileHeld(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()
	key := "lock:test:renew"

	lock, ok, err := AcquireLock(ctx, v, key, 500*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}

	ok, err = lock.Renew(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !ok {
		t.Fatal("expected Renew to report the lock is still held")
	}

	// Without the renew, the original 500ms TTL would have expired by now.
	time.Sleep(700 * time.Millisecond)
	_, ok, err = AcquireLock(ctx, v, key, time.Minute)
	if err != nil {
		t.Fatalf("acquire after renew: %v", err)
	}
	if ok {
		t.Fatal("lock expired despite being renewed")
	}
}

func TestRenewFailsAfterLockStolen(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()
	key := "lock:test:renew-stolen"

	lock, ok, err := AcquireLock(ctx, v, key, 300*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	time.Sleep(400 * time.Millisecond) // let it expire

	if _, ok, err := AcquireLock(ctx, v, key, time.Minute); err != nil || !ok {
		t.Fatalf("second acquire after expiry: ok=%v err=%v", ok, err)
	}

	ok, err = lock.Renew(ctx, time.Minute)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if ok {
		t.Fatal("expected Renew to report the lock was lost to another replica")
	}
}

func TestStartRenewingClosesLostChannelWhenLockStolen(t *testing.T) {
	v := newTestClient(t)
	ctx := context.Background()
	key := "lock:test:start-renewing"

	lock, ok, err := AcquireLock(ctx, v, key, time.Minute)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}

	lost, stop := lock.StartRenewing(ctx, time.Minute, 50*time.Millisecond)
	defer stop()

	// Simulate another replica taking over after this lock's TTL genuinely
	// expired elsewhere, by overwriting the key directly. Racing real
	// wall-clock expiry here would be flaky: the renew loop pushes the TTL
	// back out every 50ms, so a real expiry could lose the race against it.
	if err := v.Do(ctx, v.B().Set().Key(key).Value("stolen-token").Build()).Error(); err != nil {
		t.Fatalf("simulate takeover: %v", err)
	}

	select {
	case <-lost:
	case <-time.After(2 * time.Second):
		t.Fatal("expected lost channel to close after another replica took the lock")
	}
}

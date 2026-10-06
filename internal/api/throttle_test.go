package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestThrottle(limit int, window time.Duration) (*authThrottle, *time.Time) {
	t := newAuthThrottle(limit, window)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t.now = func() time.Time { return now }
	return t, &now
}

func TestThrottleAllowsBelowLimit(t *testing.T) {
	th, _ := newTestThrottle(3, time.Minute)
	th.fail("a")
	th.fail("a")
	if th.blocked("a") {
		t.Fatal("blocked after 2 failures with limit 3")
	}
}

func TestThrottleBlocksAtLimit(t *testing.T) {
	th, _ := newTestThrottle(3, time.Minute)
	for i := 0; i < 3; i++ {
		th.fail("a")
	}
	if !th.blocked("a") {
		t.Fatal("not blocked after reaching the limit")
	}
}

func TestThrottleBlockExpiresAfterWindow(t *testing.T) {
	th, now := newTestThrottle(2, time.Minute)
	th.fail("a")
	th.fail("a")
	if !th.blocked("a") {
		t.Fatal("expected block")
	}
	*now = now.Add(time.Minute + time.Second)
	if th.blocked("a") {
		t.Fatal("still blocked after the window elapsed")
	}
}

// TestThrottleWindowResetsCount guards against failures accumulating
// forever: two failures separated by more than a window must not add
// up to a block.
func TestThrottleWindowResetsCount(t *testing.T) {
	th, now := newTestThrottle(2, time.Minute)
	th.fail("a")
	*now = now.Add(2 * time.Minute)
	th.fail("a")
	if th.blocked("a") {
		t.Fatal("failures across separate windows were summed")
	}
}

func TestThrottleSourcesAreIndependent(t *testing.T) {
	th, _ := newTestThrottle(1, time.Minute)
	th.fail("a")
	if th.blocked("b") {
		t.Fatal("source b blocked by source a's failure")
	}
	if !th.blocked("a") {
		t.Fatal("source a not blocked")
	}
}

func TestThrottleResetClearsBlock(t *testing.T) {
	th, _ := newTestThrottle(1, time.Minute)
	th.fail("a")
	th.reset("a")
	if th.blocked("a") {
		t.Fatal("reset did not clear the block")
	}
}

func TestThrottleUnknownSourceNotBlocked(t *testing.T) {
	th, _ := newTestThrottle(1, time.Minute)
	if th.blocked("never-seen") {
		t.Fatal("unknown source reported blocked")
	}
}

func TestThrottleDefaultsClampNonPositive(t *testing.T) {
	th := newAuthThrottle(0, 0)
	if th.limit != defaultAuthFailureLimit {
		t.Errorf("limit %d, want %d", th.limit, defaultAuthFailureLimit)
	}
	if th.window != defaultAuthFailureWindow {
		t.Errorf("window %v, want %v", th.window, defaultAuthFailureWindow)
	}
	th = newAuthThrottle(-5, -time.Second)
	if th.limit != defaultAuthFailureLimit || th.window != defaultAuthFailureWindow {
		t.Errorf("negative inputs not clamped: %d %v", th.limit, th.window)
	}
}

// TestThrottleBoundsTrackedSources is the memory guard: a flood of
// distinct sources must not grow the map past the cap.
func TestThrottleBoundsTrackedSources(t *testing.T) {
	th, _ := newTestThrottle(100, time.Minute)
	for i := 0; i < maxTrackedSources+500; i++ {
		th.fail(fmt.Sprintf("src-%d", i))
	}
	if n := len(th.entries); n > maxTrackedSources {
		t.Errorf("tracked %d sources, cap is %d", n, maxTrackedSources)
	}
}

// TestThrottleEvictsExpiredBeforeLive confirms eviction prefers entries
// whose window has already lapsed over ones still counting.
func TestThrottleEvictsExpiredBeforeLive(t *testing.T) {
	th, now := newTestThrottle(100, time.Minute)
	th.fail("old")
	*now = now.Add(2 * time.Minute)
	for i := 0; i < maxTrackedSources-1; i++ {
		th.fail(fmt.Sprintf("live-%d", i))
	}
	// Map is now at cap; this insert must evict "old", not a live one.
	th.fail("newest")
	if _, ok := th.entries["old"]; ok {
		t.Error("expired entry survived eviction")
	}
	if _, ok := th.entries["newest"]; !ok {
		t.Error("newest entry was not inserted")
	}
}

func TestThrottleSourceStripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:54321"
	if got := throttleSource(r); got != "10.1.2.3" {
		t.Errorf("got %q, want 10.1.2.3", got)
	}
}

// TestThrottleSourceIgnoresForwardedFor is the spoofing guard: a client
// cannot pick its own throttle key by sending a header.
func TestThrottleSourceIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:54321"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	r.Header.Set("X-Real-Ip", "2.2.2.2")
	if got := throttleSource(r); got != "10.1.2.3" {
		t.Errorf("forwarded header influenced the key: %q", got)
	}
}

func TestThrottleSourceHandlesNoPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "unix-socket-peer"
	if got := throttleSource(r); got != "unix-socket-peer" {
		t.Errorf("got %q", got)
	}
}

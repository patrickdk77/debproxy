package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Authentication on /api/v1 had no brake on repeated failures. bcrypt and
// argon2 make each guess expensive for the server as well as the
// attacker, and APIAuthFailuresTotal makes a run of failures visible, but
// nothing stopped a sustained guess from continuing indefinitely. A
// per-source failure window closes that: a source that keeps failing is
// refused outright for a while, which also stops it from burning a
// password-hash computation per attempt.
//
// The source is the TCP peer, not X-Forwarded-For. A forwarded header is
// whatever the client chose to send, so keying on it would let an
// attacker rotate out of the window by lying, and let them lock out a
// victim's address by lying the other way.
const (
	// defaultAuthFailureLimit is how many failures a source may
	// accumulate inside defaultAuthFailureWindow before being refused.
	defaultAuthFailureLimit = 10
	// defaultAuthFailureWindow is both the counting window and how long
	// a tripped source stays refused.
	defaultAuthFailureWindow = time.Minute
	// maxTrackedSources bounds memory: once reached, the oldest-expiring
	// entry is evicted on insert, so a flood of distinct sources cannot
	// grow the map without limit.
	maxTrackedSources = 10000
)

type failureEntry struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

// authThrottle tracks authentication failures per source and refuses
// sources that exceed the limit within the window.
type authThrottle struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*failureEntry
	now     func() time.Time
}

func newAuthThrottle(limit int, window time.Duration) *authThrottle {
	if limit <= 0 {
		limit = defaultAuthFailureLimit
	}
	if window <= 0 {
		window = defaultAuthFailureWindow
	}
	return &authThrottle{
		limit:   limit,
		window:  window,
		entries: map[string]*failureEntry{},
		now:     time.Now,
	}
}

// blocked reports whether source is currently refused.
func (t *authThrottle) blocked(source string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[source]
	if !ok {
		return false
	}
	now := t.now()
	if !e.blockedUntil.IsZero() && now.Before(e.blockedUntil) {
		return true
	}
	if now.Sub(e.windowStart) > t.window {
		delete(t.entries, source)
	}
	return false
}

// fail records one authentication failure for source, tripping the
// block once the limit is reached within the window.
func (t *authThrottle) fail(source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.entries[source]
	if !ok || now.Sub(e.windowStart) > t.window {
		if !ok && len(t.entries) >= maxTrackedSources {
			t.evictOldest(now)
		}
		e = &failureEntry{windowStart: now}
		t.entries[source] = e
	}
	e.count++
	if e.count >= t.limit {
		e.blockedUntil = now.Add(t.window)
	}
}

// reset clears source's record after a successful authentication, so a
// legitimate caller who mistyped a few times is not penalized past the
// moment they get it right.
func (t *authThrottle) reset(source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, source)
}

// evictOldest drops the entry whose window started earliest. Caller
// holds t.mu.
func (t *authThrottle) evictOldest(now time.Time) {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range t.entries {
		if now.Sub(e.windowStart) > t.window {
			delete(t.entries, k)
			continue
		}
		if first || e.windowStart.Before(oldest) {
			oldestKey, oldest, first = k, e.windowStart, false
		}
	}
	if len(t.entries) >= maxTrackedSources && oldestKey != "" {
		delete(t.entries, oldestKey)
	}
}

// throttleSource identifies the caller for throttling purposes: the TCP
// peer address with any port stripped. See the package comment above for
// why forwarded headers are deliberately ignored here.
func throttleSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

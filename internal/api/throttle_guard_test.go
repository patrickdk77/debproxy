package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/auth"
	"github.com/debproxy/debproxy/internal/config"
)

func guardReq(user, pass, remote string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	req.SetBasicAuth(user, pass)
	req.RemoteAddr = remote
	return req
}

// TestGuardThrottlesAfterRepeatedFailures is the integration test for the
// brute-force brake: once a source has failed the configured number of
// times, its next attempt is refused with 429 before credentials are
// even examined.
func TestGuardThrottlesAfterRepeatedFailures(t *testing.T) {
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(3, time.Minute)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h(rec, guardReq("alice", "wrong", "10.0.0.1:1000"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: status %d, want 403", i+1, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h(rec, guardReq("alice", "wrong", "10.0.0.1:2000"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after limit: status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After header")
	}
}

// TestGuardThrottleBlocksEvenCorrectPassword proves the check runs before
// authentication: a tripped source is refused even with the right
// credential, so the brake cannot be probed around by guessing right.
func TestGuardThrottleBlocksEvenCorrectPassword(t *testing.T) {
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(2, time.Minute)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	for i := 0; i < 2; i++ {
		h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.2:1"))
	}
	rec := httptest.NewRecorder()
	h(rec, guardReq("alice", "s3cret", "10.0.0.2:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password bypassed throttle: status %d", rec.Code)
	}
}

// TestGuardThrottleIsPerSource guards the other direction: one source
// being throttled must not affect a different one.
func TestGuardThrottleIsPerSource(t *testing.T) {
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(1, time.Minute)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.3:1"))

	rec := httptest.NewRecorder()
	h(rec, guardReq("alice", "s3cret", "10.0.0.4:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("unrelated source affected: status %d, want 200", rec.Code)
	}
}

// TestGuardSuccessResetsFailureCount covers a legitimate caller who
// mistypes a few times then gets it right: the slate is wiped, so the
// earlier misses do not count toward a later block.
func TestGuardSuccessResetsFailureCount(t *testing.T) {
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(3, time.Minute)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.5:1"))
	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.5:1"))
	rec := httptest.NewRecorder()
	h(rec, guardReq("alice", "s3cret", "10.0.0.5:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid login after 2 misses: status %d", rec.Code)
	}

	// Two more misses would have tripped limit 3 if the count persisted.
	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.5:1"))
	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.5:1"))
	rec = httptest.NewRecorder()
	h(rec, guardReq("alice", "s3cret", "10.0.0.5:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("count was not reset on success: status %d", rec.Code)
	}
}

// TestGuardNotPermittedCountsAsFailure: a valid credential for an
// identity that is not allow-listed is still a failed attempt from the
// throttle's point of view, so enumeration by valid-but-unlisted
// accounts is braked the same way.
func TestGuardNotPermittedCountsAsFailure(t *testing.T) {
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(2, time.Minute)
	// Add bob with a valid hash but no allow-list entry.
	a.cfg.API[ResSnapshot][ActCreate] = []string{"alice"}
	var err error
	a.authn, err = newAuthWithUsers(t, map[string]string{
		"alice": mustBcryptHash(t, "s3cret"),
		"bob":   mustBcryptHash(t, "s3cret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h(rec, guardReq("bob", "s3cret", "10.0.0.6:1"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("bob attempt %d: status %d, want 403", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h(rec, guardReq("bob", "s3cret", "10.0.0.6:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("not-permitted attempts did not trip throttle: %d", rec.Code)
	}
}

// TestGuardNoCredentialsDoesNotCountAsFailure: a bare request with no
// Authorization header is a 401, not an attempt, and must not advance
// the counter -- otherwise a health check or a misconfigured client
// could lock out a shared address.
func TestGuardNoCredentialsDoesNotCountAsFailure(t *testing.T) {
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(1, time.Minute)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	bare := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	bare.RemoteAddr = "10.0.0.7:1"
	for i := 0; i < 5; i++ {
		h(httptest.NewRecorder(), bare)
	}
	rec := httptest.NewRecorder()
	h(rec, guardReq("alice", "s3cret", "10.0.0.7:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("401s counted toward the throttle: status %d", rec.Code)
	}
}

func newAuthWithUsers(t *testing.T, users map[string]string) (*auth.Authenticator, error) {
	t.Helper()
	return auth.New(authCfgWithBasic(users), nil)
}

func authCfgWithBasic(users map[string]string) config.AuthConfig {
	return config.AuthConfig{Basic: users}
}

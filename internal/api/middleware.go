package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/debproxy/debproxy/internal/auth"
	"github.com/debproxy/debproxy/internal/metrics"
)

// guardedHandler is an /api/v1 handler that runs only once guard's request
// flow (below) has authenticated and authorized the caller.
type guardedHandler func(w http.ResponseWriter, r *http.Request, identity auth.Identity)

// guard implements the request flow that is this design's core security
// property:
//
//  1. Look up cfg.API[resource][action]. Missing/empty -> 404, checked
//     BEFORE authentication, so an unconfigured action is indistinguishable
//     from a nonexistent one -- an unconfigured instance leaks nothing about
//     what actions exist.
//  2. No Authorization header at all -> 401.
//  3. Authenticate + authorize. Any header present that doesn't resolve to
//     an allow-listed identity -> 403 -- this deliberately collapses
//     invalid credentials (bad Basic password, bad/expired/unverifiable
//     Bearer, Bearer naming no configured issuer) AND
//     authenticated-but-not-allow-listed into one 403. 401 is reserved
//     strictly for "sent nothing"; the response never distinguishes "wrong
//     credential" from "not permitted" (no user/permission enumeration).
//  4. Handler runs -> 2xx.
func (a *API) guard(resource, action string, next guardedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules := a.cfg.API[resource][action]
		if len(rules) == 0 {
			http.NotFound(w, r)
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusNotFound)).Inc()
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="debproxy"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			metrics.APIAuthFailuresTotal.WithLabelValues("no_credentials").Inc()
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusUnauthorized)).Inc()
			return
		}
		// Checked before any credential is examined, so a source that has
		// tripped the limit costs nothing further: no hash computation, no
		// JWKS lookup, and no information about why its last attempts
		// failed. 429 rather than 403 so a legitimate caller stuck behind a
		// shared address can tell "wait" from "wrong".
		source := throttleKey(r)
		if a.throttle.blocked(source) {
			w.Header().Set("Retry-After", strconv.Itoa(int(a.throttle.window.Seconds())))
			http.Error(w, "too many failed authentication attempts", http.StatusTooManyRequests)
			logAuthFailure(r, resource, action, "throttled")
			metrics.APIAuthFailuresTotal.WithLabelValues("throttled").Inc()
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusTooManyRequests)).Inc()
			return
		}
		// Charged before the credential is examined and refunded on
		// success. Charging only after a failure left a window between
		// the check above and the verify below in which any number of
		// concurrent attempts all passed; charging first means the limit
		// trips while they are still in flight.
		a.throttle.fail(source)
		identity, err := a.authn.Authenticate(r)
		if err != nil {
			logAuthFailure(r, resource, action, "invalid_credentials")
			metrics.APIAuthFailuresTotal.WithLabelValues("invalid_credentials").Inc()
			http.Error(w, "forbidden", http.StatusForbidden)
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusForbidden)).Inc()
			return
		}
		if !Allowed(rules, identity) {
			logAuthFailure(r, resource, action, "not_permitted")
			metrics.APIAuthFailuresTotal.WithLabelValues("not_permitted").Inc()
			http.Error(w, "forbidden", http.StatusForbidden)
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusForbidden)).Inc()
			return
		}
		a.throttle.reset(source)

		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(sw, r, identity)
		metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(sw.status)).Inc()
	}
}

// statusRecorder captures the status code a handler writes, for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logAuthFailure is the audit record for a refused API request. The
// metrics count these; this names the account and the peer, which is
// what an operator needs to tell a mistyped password from a guessing
// run. Only the Basic username is known before verification; a bearer
// request is recorded by peer alone.
func logAuthFailure(r *http.Request, resource, action, reason string) {
	user := "-"
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		user = u
	}
	slog.Warn("api request refused",
		"user", user, "peer", throttleSource(r),
		"resource", resource, "action", action, "reason", reason)
}

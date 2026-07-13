package api

import (
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
		identity, err := a.authn.Authenticate(r)
		if err != nil {
			metrics.APIAuthFailuresTotal.WithLabelValues("invalid_credentials").Inc()
			http.Error(w, "forbidden", http.StatusForbidden)
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusForbidden)).Inc()
			return
		}
		if !Allowed(rules, identity) {
			metrics.APIAuthFailuresTotal.WithLabelValues("not_permitted").Inc()
			http.Error(w, "forbidden", http.StatusForbidden)
			metrics.APIRequestsTotal.WithLabelValues(resource, action, strconv.Itoa(http.StatusForbidden)).Inc()
			return
		}

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

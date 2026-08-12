package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"time"
)

// serveKeyFromMemory answers a /keys/* request from the in-memory
// signing key, reporting whether it handled the request.
//
// The public key files are derived entirely from the loaded signing
// key (see signing.Key.PublishedPayloads) and never change while the
// process runs, so there is no reason to read them back out of the
// storage backend. Doing so put a constant ~1.6KB file behind a
// storage round trip on the hot path for every apt client, which made
// key retrieval fail whenever the backend was slow -- even though the
// bytes were already in this process the whole time.
//
// Returns false when the key is unavailable or the requested name is
// not one this key publishes, leaving the caller to fall back to the
// storage-backed path.
func (s *Server) serveKeyFromMemory(w http.ResponseWriter, r *http.Request, relPath string) bool {
	payloads := s.publishedKeyPayloads()
	body, ok := payloads[relPath]
	if !ok {
		return false
	}

	sum := sha256.Sum256(body)
	w.Header().Set("Cache-Control", httpCacheControl(r.URL.Path))
	w.Header().Set("Content-Type", contentType(relPath))
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	// A zero modtime keeps ServeContent from emitting Last-Modified,
	// which would otherwise be this process's start time and differ
	// between replicas serving identical bytes.
	http.ServeContent(w, r, path.Base(relPath), time.Time{},
		bytes.NewReader(body))
	return true
}

// publishedKeyPayloads renders the key files once and caches them. A
// nil key, or a key that fails to serialize, yields a nil map so
// callers fall back to the storage-backed path rather than failing.
func (s *Server) publishedKeyPayloads() map[string][]byte {
	s.keyPayloadsOnce.Do(func() {
		if s.key == nil {
			return
		}
		payloads, err := s.key.PublishedPayloads()
		if err != nil {
			slog.Warn("render published key payloads for "+
				"in-memory serving; falling back to storage",
				"err", err)
			return
		}
		s.keyPayloads = payloads
	})
	return s.keyPayloads
}

// clientGone reports whether err is the result of the client hanging
// up rather than a real backend failure.
//
// Every storage call inherits the request context, so an apt client
// that times out and disconnects cancels whatever S3 operation was in
// flight. Treating that as a server error logged it at ERROR and wrote
// a 500 to a socket nobody was reading, which made ordinary client
// timeouts look like backend faults in the logs and inflated the error
// rate with responses no client ever saw.
func clientGone(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

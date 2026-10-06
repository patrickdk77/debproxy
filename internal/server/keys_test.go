package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
)

// failingStore fails every published read, standing in for a storage
// backend that is down or hanging. A key served from memory must not
// touch it at all.
type failingStore struct {
	storage.Storage
	reads int
}

func (f *failingStore) StatPublished(ctx context.Context, rel string) (
	storage.FileInfo, error) {
	f.reads++
	return storage.FileInfo{}, fmt.Errorf("storage is down")
}

func (f *failingStore) OpenPublished(ctx context.Context, rel string) (
	io.ReadCloser, error) {
	f.reads++
	return nil, fmt.Errorf("storage is down")
}

// testKey reuses the package's existing signing-key helper (see
// rebuildlive_internal_test.go) rather than adding a second one.
func testKey(t *testing.T) *signing.Key {
	t.Helper()
	key, _ := testSigningKey(t)
	return key
}

// TestKeysServedWithoutTouchingStorage is the regression test for the
// production failure: the public key is static and already in memory,
// so a storage backend that is completely broken must not stop apt
// from fetching it.
func TestKeysServedWithoutTouchingStorage(t *testing.T) {
	key := testKey(t)
	store := &failingStore{}
	s := &Server{key: key, store: store}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for _, name := range []string{
		"/keys/debproxy.asc",
		"/keys/debproxy.gpg",
	} {
		resp, err := http.Get(srv.URL + name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s body: %v", name, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
		if len(body) == 0 {
			t.Errorf("%s: empty body", name)
		}
		if resp.Header.Get("ETag") == "" {
			t.Errorf("%s: no ETag", name)
		}
	}
	if store.reads != 0 {
		t.Errorf("storage was read %d times; keys must be served "+
			"entirely from memory", store.reads)
	}
}

func TestArmoredKeyContentIsAnArmoredBlock(t *testing.T) {
	key := testKey(t)
	s := &Server{key: key, store: &failingStore{}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/keys/debproxy.asc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Errorf("not an armored key block: %.80s", string(body))
	}
}

// TestFingerprintNamedKeysAlsoServedFromMemory covers the other two
// names PublishedNames advertises.
func TestFingerprintNamedKeysAlsoServedFromMemory(t *testing.T) {
	key := testKey(t)
	store := &failingStore{}
	s := &Server{key: key, store: store}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	for _, name := range key.PublishedNames() {
		resp, err := http.Get(srv.URL + "/" + name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}
	if store.reads != 0 {
		t.Errorf("storage read %d times for published key names",
			store.reads)
	}
}

// TestUnknownKeyNameFallsBackToStorage guards the fallback: a name the
// key does not publish must still go through the storage path rather
// than 404ing from memory.
func TestUnknownKeyNameFallsBackToStorage(t *testing.T) {
	key := testKey(t)
	store := &failingStore{}
	s := &Server{key: key, store: store}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/keys/some-other-key.asc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if store.reads == 0 {
		t.Error("unknown key name did not fall back to storage")
	}
}

// TestNilKeyFallsBackToStorage covers a Server built without a signing
// key, which must not panic.
func TestNilKeyFallsBackToStorage(t *testing.T) {
	store := &failingStore{}
	s := &Server{key: nil, store: store}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/keys/debproxy.asc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if store.reads == 0 {
		t.Error("nil key did not fall back to storage")
	}
}

func TestClientGoneClassification(t *testing.T) {
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"real backend error", live,
			errors.New("s3 is down"), false},
		{"not-exist", live, os.ErrNotExist, false},
		{"wrapped cancel", live,
			fmt.Errorf("s3 stat: %w", context.Canceled), true},
		{"wrapped deadline", live,
			fmt.Errorf("s3 get: %w", context.DeadlineExceeded), true},
		{"cancelled ctx, unrelated err", cancelled,
			errors.New("s3 is down"), true},
	}
	for _, tc := range cases {
		if got := clientGone(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// cancelStore returns a context error from every read, standing in for
// a storage call that was aborted because the client hung up.
type cancelStore struct {
	storage.Storage
	calls int
}

func (c *cancelStore) StatPublished(ctx context.Context, rel string) (
	storage.FileInfo, error) {
	c.calls++
	return storage.FileInfo{}, fmt.Errorf("s3 stat %q: %w", rel,
		context.Canceled)
}

func (c *cancelStore) OpenPublished(ctx context.Context, rel string) (
	io.ReadCloser, error) {
	c.calls++
	return nil, fmt.Errorf("s3 open %q: %w", rel, context.Canceled)
}

func (c *cancelStore) Stat(ctx context.Context, p string) (
	storage.FileInfo, error) {
	c.calls++
	return storage.FileInfo{}, fmt.Errorf("s3 stat %q: %w", p,
		context.Canceled)
}

func (c *cancelStore) Open(ctx context.Context, p string) (
	io.ReadCloser, error) {
	c.calls++
	return nil, fmt.Errorf("s3 open %q: %w", p, context.Canceled)
}

// TestServePublishedDoesNotErrorOnClientCancel covers the call site,
// not just the clientGone helper. Removing the clientGone guard from
// servePublished must fail this test: a storage read aborted by the
// client hanging up has to leave the response untouched rather than
// writing a 500 nobody is reading.
func TestServePublishedDoesNotErrorOnClientCancel(t *testing.T) {
	store := &cancelStore{}
	s := &Server{store: store}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet,
		"/current/debian/dists/trixie/InRelease", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	s.servePublished(rec, req, "current/debian/dists/trixie/InRelease")

	if store.calls == 0 {
		t.Fatal("storage was never consulted; test proves nothing")
	}
	if rec.Code == http.StatusInternalServerError {
		t.Errorf("client cancellation reported as a 500")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("wrote %d bytes to a client that hung up: %q",
			rec.Body.Len(), rec.Body.String())
	}
}

// TestServePublishedStillErrorsOnRealFailure is the other half: a
// genuine backend failure with a live client must still surface as a
// 500, so the clientGone guard cannot be widened into swallowing real
// errors.
func TestServePublishedStillErrorsOnRealFailure(t *testing.T) {
	store := &failingStore{}
	s := &Server{store: store}

	req := httptest.NewRequest(http.MethodGet,
		"/current/debian/dists/trixie/InRelease", nil)
	rec := httptest.NewRecorder()

	s.servePublished(rec, req, "current/debian/dists/trixie/InRelease")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("real backend failure returned %d, want 500", rec.Code)
	}
}

// TestServerErrorBodyDoesNotEchoBackendError is the regression test for
// raw err.Error() reaching clients. A backend failure names buckets,
// keys and hosts; none of that may appear in the response body.
func TestServerErrorBodyDoesNotEchoBackendError(t *testing.T) {
	store := &failingStore{}
	s := &Server{store: store}

	req := httptest.NewRequest(http.MethodGet,
		"/current/debian/dists/trixie/InRelease", nil)
	rec := httptest.NewRecorder()
	s.servePublished(rec, req, "current/debian/dists/trixie/InRelease")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "storage is down") {
		t.Errorf("backend error text leaked to client: %q", body)
	}
	if strings.TrimSpace(body) != internalErrorBody {
		t.Errorf("body %q, want %q", strings.TrimSpace(body), internalErrorBody)
	}
}

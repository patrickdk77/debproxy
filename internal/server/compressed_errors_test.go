package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/debproxy/debproxy/internal/storage"
)

// compressedFailStore has no plain file (Stat says not-exist, so the
// compressed path is taken) and fails every compressed open with a
// non-not-exist error.
type compressedFailStore struct {
	storage.Storage
	openErr error
}

func (c *compressedFailStore) StatPublished(ctx context.Context, rel string) (storage.FileInfo, error) {
	return storage.FileInfo{}, os.ErrNotExist
}

func (c *compressedFailStore) OpenPublished(ctx context.Context, rel string) (io.ReadCloser, error) {
	return nil, c.openErr
}

// TestCompressedIndexBackendErrorIsNot404 is the regression test for a
// storage failure being reported to apt as a missing index.
func TestCompressedIndexBackendErrorIsNot404(t *testing.T) {
	s := &Server{store: &compressedFailStore{openErr: fmt.Errorf("s3: access denied")}}
	req := httptest.NewRequest(http.MethodGet, "/current/debian/dists/trixie/main/binary-amd64/Packages", nil)
	rec := httptest.NewRecorder()
	s.servePublished(rec, req, "current/debian/dists/trixie/main/binary-amd64/Packages")

	if rec.Code == http.StatusNotFound {
		t.Fatal("backend failure reported as 404")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
}

// TestCompressedIndexTrulyMissingIs404 keeps the other side honest: when
// every variant really is absent, the answer is still 404.
func TestCompressedIndexTrulyMissingIs404(t *testing.T) {
	s := &Server{store: &compressedFailStore{openErr: os.ErrNotExist}}
	req := httptest.NewRequest(http.MethodGet, "/current/debian/dists/trixie/main/binary-amd64/Packages", nil)
	rec := httptest.NewRecorder()
	s.servePublished(rec, req, "current/debian/dists/trixie/main/binary-amd64/Packages")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for a truly missing index", rec.Code)
	}
}

func TestCompressedIndexClientCancelIsSilent(t *testing.T) {
	s := &Server{store: &compressedFailStore{openErr: fmt.Errorf("s3: %w", context.Canceled)}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.servePublished(rec, req, "current/debian/dists/trixie/main/binary-amd64/Packages")
	if rec.Code == http.StatusInternalServerError || rec.Body.Len() != 0 {
		t.Fatalf("client cancel produced status %d with %d bytes", rec.Code, rec.Body.Len())
	}
	if !errors.Is(context.Canceled, context.Canceled) {
		t.Fatal("sanity")
	}
}

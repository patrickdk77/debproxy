package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/storage"
)

// listingStore counts ListSnapshots calls and returns a fixed set.
type listingStore struct {
	storage.Storage
	refs  []storage.SnapshotRef
	calls int
}

func (l *listingStore) ListSnapshots(ctx context.Context, osName string) ([]storage.SnapshotRef, error) {
	l.calls++
	return l.refs, nil
}

func (l *listingStore) ResolveSnapshot(ctx context.Context, osName string, at time.Time) (string, error) {
	panic("ResolveSnapshot must not be called; dates resolve from the cached listing")
}

func day(d int) time.Time {
	return time.Date(2026, 10, d, 12, 0, 0, 0, time.UTC)
}

func snapServer(store *listingStore) *Server {
	return &Server{
		store:           store,
		validOS:         map[string]bool{"debian": true},
		validOSCodename: map[string]bool{"debian/trixie": true},
	}
}

func threeSnapshots() []storage.SnapshotRef {
	return []storage.SnapshotRef{
		{ID: "2026-10-01T12-00-00", OS: "debian", CreatedAt: day(1)},
		{ID: "2026-10-10T12-00-00", OS: "debian", CreatedAt: day(10)},
		{ID: "2026-10-20T12-00-00", OS: "debian", CreatedAt: day(20)},
	}
}

// TestResolveSnapshotListsOncePerTTL is the regression test for one
// storage LIST per request under a dated selector.
func TestResolveSnapshotListsOncePerTTL(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		if _, err := s.resolveSnapshot(ctx, "debian", "2026-10-10T12-00-00"); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if _, err := s.resolveSnapshot(ctx, "debian", "2026-10-15"); err != nil {
			t.Fatalf("date resolve %d: %v", i, err)
		}
	}
	if store.calls != 1 {
		t.Fatalf("ListSnapshots called %d times for 50 resolves, want 1", store.calls)
	}
}

func TestResolveSnapshotRelistsAfterTTL(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	ctx := context.Background()
	if _, err := s.resolveSnapshot(ctx, "debian", "2026-10-10T12-00-00"); err != nil {
		t.Fatal(err)
	}
	s.snapListMu.Lock()
	e := s.snapList["debian"]
	e.at = time.Now().Add(-2 * snapListTTL)
	s.snapList["debian"] = e
	s.snapListMu.Unlock()
	if _, err := s.resolveSnapshot(ctx, "debian", "2026-10-10T12-00-00"); err != nil {
		t.Fatal(err)
	}
	if store.calls != 2 {
		t.Fatalf("ListSnapshots called %d times across a TTL expiry, want 2", store.calls)
	}
}

// TestResolveSnapshotDateResolvesFromCache: a date selector picks the
// newest snapshot at or before that day without a second storage call.
func TestResolveSnapshotDateResolvesFromCache(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	cases := map[string]string{
		"2026-10-15":          "2026-10-10T12-00-00",
		"2026-10-10":          "2026-10-10T12-00-00",
		"2026-10-25":          "2026-10-20T12-00-00",
		"2026-10-10T11-59-59": "2026-10-01T12-00-00",
	}
	for sel, want := range cases {
		got, err := s.resolveSnapshot(context.Background(), "debian", sel)
		if err != nil {
			t.Errorf("%s: %v", sel, err)
			continue
		}
		if got != want {
			t.Errorf("%s -> %s, want %s", sel, got, want)
		}
	}
	if store.calls != 1 {
		t.Errorf("ListSnapshots called %d times, want 1", store.calls)
	}
}

// TestResolveSnapshotDateBeforeFirstIsNotFound: previously a 502, since a
// plain error came back from the store; it is a client asking for a
// nonexistent thing.
func TestResolveSnapshotDateBeforeFirstIsNotFound(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	_, err := s.resolveSnapshot(context.Background(), "debian", "2025-01-01")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}

// TestResolveSnapshotUnknownOSSkipsListing is the scanner guard: a path
// whose os no layout defines is refused before any storage call.
func TestResolveSnapshotUnknownOSSkipsListing(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	_, err := s.resolveSnapshot(context.Background(), "wp-admin", "2026-10-10")
	if !errors.Is(err, errUnknownSelector) {
		t.Fatalf("err = %v, want errUnknownSelector", err)
	}
	if store.calls != 0 {
		t.Fatalf("ListSnapshots called %d times for an unknown os", store.calls)
	}
}

func TestResolveSnapshotGarbageSelectorIsUnknown(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	_, err := s.resolveSnapshot(context.Background(), "debian", "not-a-date")
	if !errors.Is(err, errUnknownSelector) {
		t.Fatalf("err = %v, want errUnknownSelector", err)
	}
}

func TestResolveSnapshotCurrentNeverLists(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	id, err := s.resolveSnapshot(context.Background(), "debian", "current")
	if err != nil || id != "current" {
		t.Fatalf("got %q, %v", id, err)
	}
	if store.calls != 0 {
		t.Fatalf("current selector listed snapshots %d times", store.calls)
	}
}

// TestHandleSnapshotUnknownOSIs404 drives the guard through the router.
func TestHandleSnapshotUnknownOSIs404(t *testing.T) {
	store := &listingStore{refs: threeSnapshots()}
	s := snapServer(store)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/2026-10-10/wp-admin/x/y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if store.calls != 0 {
		t.Fatalf("storage listed %d times for a scanner path", store.calls)
	}
}

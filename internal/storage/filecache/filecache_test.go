package filecache_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/filecache"
)

// mockStore is a minimal storage.Storage backing store that records how
// many times each read/write method was called, so tests can assert a
// cache hit never reaches the backend and a cache miss (or a write) does.
type mockStore struct {
	mu    sync.Mutex
	files map[string][]byte

	openCalls, statCalls, existsCalls           int
	openPubCalls, statPubCalls                  int
	writeCalls, putCalls, delCalls, delPubCalls int
}

func newMockStore() *mockStore {
	return &mockStore{files: map[string][]byte{}}
}

func (m *mockStore) set(path string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = data
}

func (m *mockStore) Open(_ context.Context, path string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.openCalls++
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockStore) Stat(_ context.Context, path string) (storage.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statCalls++
	data, ok := m.files[path]
	if !ok {
		return storage.FileInfo{}, os.ErrNotExist
	}
	return storage.FileInfo{Path: path, Size: int64(len(data))}, nil
}

func (m *mockStore) Exists(_ context.Context, path string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.existsCalls++
	_, ok := m.files[path]
	return ok, nil
}

func (m *mockStore) PutFile(_ context.Context, path string, r io.Reader, _ int64) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putCalls++
	m.files[path] = data
	return nil
}

func (m *mockStore) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delCalls++
	delete(m.files, path)
	return nil
}

func (m *mockStore) ComputeChecksums(context.Context, string) (model.Checksums, error) {
	return model.Checksums{}, storage.ErrNotImplemented
}

func (m *mockStore) WalkPool(context.Context, func(storage.FileInfo) error) error {
	return storage.ErrNotImplemented
}

func (m *mockStore) WriteFile(_ context.Context, path string, r io.Reader, _ int64) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalls++
	m.files[path] = data
	return nil
}

func (m *mockStore) DeletePublished(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delPubCalls++
	delete(m.files, path)
	return nil
}

func (m *mockStore) OpenPublished(_ context.Context, path string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.openPubCalls++
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockStore) StatPublished(_ context.Context, path string) (storage.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statPubCalls++
	data, ok := m.files[path]
	if !ok {
		return storage.FileInfo{}, os.ErrNotExist
	}
	return storage.FileInfo{Path: path, Size: int64(len(data))}, nil
}

func (m *mockStore) ListPublished(context.Context, string) ([]string, error) {
	return nil, storage.ErrNotImplemented
}

func (m *mockStore) ListPublishedInfo(context.Context, string) ([]storage.FileInfo, error) {
	return nil, storage.ErrNotImplemented
}

func (m *mockStore) ListSnapshots(context.Context, string) ([]storage.SnapshotRef, error) {
	return nil, storage.ErrNotImplemented
}

func (m *mockStore) ResolveSnapshot(context.Context, string, time.Time) (string, error) {
	return "", storage.ErrNotImplemented
}

func (m *mockStore) Ping(context.Context) error { return nil }

func mustRead(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

func TestWrap_DisabledReturnsUnderlyingStoreUnchanged(t *testing.T) {
	backing := newMockStore()
	wrapped := filecache.Wrap(backing, 0)
	if wrapped != storage.Storage(backing) {
		t.Fatal("expected Wrap(store, 0) to return the underlying store unchanged")
	}
}

func TestOpen_CacheHitAvoidsBackend(t *testing.T) {
	backing := newMockStore()
	backing.set("pool/a.deb", []byte("hello"))
	store := filecache.Wrap(backing, 1<<20)
	ctx := context.Background()

	rc, err := store.Open(ctx, "pool/a.deb")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if got := mustRead(t, rc); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if backing.openCalls != 1 {
		t.Fatalf("expected 1 backend Open call after first read, got %d", backing.openCalls)
	}

	// Second read of the same path must be served entirely from cache.
	rc2, err := store.Open(ctx, "pool/a.deb")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if got := mustRead(t, rc2); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if backing.openCalls != 1 {
		t.Fatalf("expected no additional backend Open call on cache hit, got %d total", backing.openCalls)
	}
}

func TestStatAndExists_CacheHitAvoidsBackend(t *testing.T) {
	backing := newMockStore()
	backing.set("pool/a.deb", []byte("hello"))
	store := filecache.Wrap(backing, 1<<20)
	ctx := context.Background()

	if _, err := store.Open(ctx, "pool/a.deb"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Open's own cache-miss path makes one real Stat call itself, to
	// pre-screen the file's size before deciding whether to buffer it (see
	// cachedOpen) -- that's the baseline to compare against below, not 0.
	statCallsAfterOpen := backing.statCalls

	info, err := store.Stat(ctx, "pool/a.deb")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size != 5 {
		t.Fatalf("got size %d, want 5", info.Size)
	}
	if backing.statCalls != statCallsAfterOpen {
		t.Fatalf("expected Stat to be served from cache (populated by Open), got %d more backend calls", backing.statCalls-statCallsAfterOpen)
	}

	exists, err := store.Exists(ctx, "pool/a.deb")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected Exists to report true from cache")
	}
	if backing.existsCalls != 0 {
		t.Fatalf("expected Exists to be served from cache, got %d backend calls", backing.existsCalls)
	}
}

func TestOpenPublished_CachesSeparatelyFromPoolPaths(t *testing.T) {
	backing := newMockStore()
	backing.set("current/debian/dists/trixie/Release", []byte("release-bytes"))
	store := filecache.Wrap(backing, 1<<20)
	ctx := context.Background()

	if _, err := store.OpenPublished(ctx, "current/debian/dists/trixie/Release"); err != nil {
		t.Fatalf("first OpenPublished: %v", err)
	}
	if backing.openPubCalls != 1 {
		t.Fatalf("expected 1 backend OpenPublished call, got %d", backing.openPubCalls)
	}
	if _, err := store.OpenPublished(ctx, "current/debian/dists/trixie/Release"); err != nil {
		t.Fatalf("second OpenPublished: %v", err)
	}
	if backing.openPubCalls != 1 {
		t.Fatalf("expected cache hit on second OpenPublished, got %d total backend calls", backing.openPubCalls)
	}
}

func TestPutFile_InvalidatesCachedEntry(t *testing.T) {
	backing := newMockStore()
	backing.set("pool/a.deb", []byte("v1"))
	store := filecache.Wrap(backing, 1<<20)
	ctx := context.Background()

	if _, err := store.Open(ctx, "pool/a.deb"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := store.PutFile(ctx, "pool/a.deb", bytes.NewReader([]byte("v2")), 2); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	rc, err := store.Open(ctx, "pool/a.deb")
	if err != nil {
		t.Fatalf("Open after PutFile: %v", err)
	}
	if got := mustRead(t, rc); got != "v2" {
		t.Fatalf("got %q, want %q (stale cache not invalidated on write)", got, "v2")
	}
}

func TestWriteFile_InvalidatesCachedEntry(t *testing.T) {
	backing := newMockStore()
	backing.set("current/debian/snapshot-name", []byte("2026-01-01"))
	store := filecache.Wrap(backing, 1<<20)
	ctx := context.Background()

	if _, err := store.OpenPublished(ctx, "current/debian/snapshot-name"); err != nil {
		t.Fatalf("OpenPublished: %v", err)
	}

	if err := store.WriteFile(ctx, "current/debian/snapshot-name", bytes.NewReader([]byte("2026-02-01")), 10); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rc, err := store.OpenPublished(ctx, "current/debian/snapshot-name")
	if err != nil {
		t.Fatalf("OpenPublished after WriteFile: %v", err)
	}
	if got := mustRead(t, rc); got != "2026-02-01" {
		t.Fatalf("got %q, want fresh content (stale cache not invalidated on write)", got)
	}
}

func TestDelete_InvalidatesCachedEntry(t *testing.T) {
	backing := newMockStore()
	backing.set("pool/a.deb", []byte("hello"))
	store := filecache.Wrap(backing, 1<<20)
	ctx := context.Background()

	if _, err := store.Open(ctx, "pool/a.deb"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.Delete(ctx, "pool/a.deb"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Open(ctx, "pool/a.deb"); !os.IsNotExist(err) {
		t.Fatalf("expected os.IsNotExist after Delete, got %v (stale cache not invalidated)", err)
	}
}

func TestEntryLargerThanOneTenthOfCacheIsNeverCached(t *testing.T) {
	backing := newMockStore()
	// Cache is 1000 bytes; max single entry is 100 bytes (1/10th).
	big := bytes.Repeat([]byte("x"), 200)
	backing.set("pool/big.deb", big)
	store := filecache.Wrap(backing, 1000)
	ctx := context.Background()

	if _, err := store.Open(ctx, "pool/big.deb"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if backing.openCalls != 1 {
		t.Fatalf("got %d open calls", backing.openCalls)
	}

	// A second read must hit the backend again -- the file was never cached.
	if _, err := store.Open(ctx, "pool/big.deb"); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if backing.openCalls != 2 {
		t.Fatalf("expected the oversized file to never be cached (2 backend calls), got %d", backing.openCalls)
	}
}

// entrySize/numEntries/lruMaxBytes set up the shared fixture for the two
// eviction tests below. The 1/10th max-entry rule (maxEntryBytes =
// maxBytes/10) means a single entry is only ever cacheable when maxBytes >=
// 10*entrySize -- so demonstrating *eviction* (total budget exceeded) with
// same-sized entries requires more than 10 of them; a 2-or-3-entry cache
// can never show both "this entry fits" and "the cache is full" under this
// rule. lruMaxBytes fits exactly numEntries-1 of the numEntries entries.
const (
	entrySize   = 10
	numEntries  = 11
	lruMaxBytes = entrySize * (numEntries - 1) // 100: room for 10 of the 11
)

func fillLRUFixture(t *testing.T) (*mockStore, storage.Storage, []string) {
	t.Helper()
	backing := newMockStore()
	names := make([]string, numEntries)
	for i := 0; i < numEntries; i++ {
		name := string([]byte{'a' + byte(i)})
		names[i] = name
		backing.set(name, bytes.Repeat([]byte{'a' + byte(i)}, entrySize))
	}
	store := filecache.Wrap(backing, lruMaxBytes)
	return backing, store, names
}

func TestLRUEviction_OldestUntouchedEntryEvictedFirst(t *testing.T) {
	backing, store, names := fillLRUFixture(t)
	ctx := context.Background()

	for _, name := range names {
		if _, err := store.Open(ctx, name); err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
	}
	callsAfterFill := backing.openCalls // one per entry, none touched twice yet

	// names[0] is the least recently used entry (opened first, never
	// touched again) and the cache only had room for 10 of the 11 -- it
	// must have been evicted, so reading it again hits the backend.
	if _, err := store.Open(ctx, names[0]); err != nil {
		t.Fatalf("re-Open(%s): %v", names[0], err)
	}
	if backing.openCalls != callsAfterFill+1 {
		t.Fatalf("expected the oldest entry to have been evicted (1 more backend call), got %d (was %d after fill)",
			backing.openCalls, callsAfterFill)
	}

	// The most recently filled entry must still be cached.
	last := names[numEntries-1]
	callsBeforeLastCheck := backing.openCalls
	if _, err := store.Open(ctx, last); err != nil {
		t.Fatalf("re-Open(%s): %v", last, err)
	}
	if backing.openCalls != callsBeforeLastCheck {
		t.Fatalf("expected the most recently used entry to still be cached, got an extra backend call")
	}
}

func TestLRUEviction_RecentlyTouchedEntrySurvives(t *testing.T) {
	backing, store, names := fillLRUFixture(t)
	ctx := context.Background()

	// Fill with the first numEntries-1 (10) entries, exactly at capacity.
	for _, name := range names[:numEntries-1] {
		if _, err := store.Open(ctx, name); err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
	}
	// Touch names[0] again, moving it to the front (most recently used).
	if _, err := store.Open(ctx, names[0]); err != nil {
		t.Fatalf("re-Open(%s): %v", names[0], err)
	}
	callsBeforeOverflow := backing.openCalls

	// Adding the 11th, brand-new entry forces one eviction. names[0] was
	// just refreshed, so names[1] -- untouched since the initial fill --
	// is now the least recently used and must be the one evicted.
	last := names[numEntries-1]
	if _, err := store.Open(ctx, last); err != nil {
		t.Fatalf("Open(%s): %v", last, err)
	}
	if backing.openCalls != callsBeforeOverflow+1 {
		t.Fatalf("expected exactly one backend call for the new entry, got %d more", backing.openCalls-callsBeforeOverflow)
	}

	// names[0] (refreshed) must still be cached.
	callsBeforeCheck := backing.openCalls
	if _, err := store.Open(ctx, names[0]); err != nil {
		t.Fatalf("re-Open(%s): %v", names[0], err)
	}
	if backing.openCalls != callsBeforeCheck {
		t.Fatalf("expected the recently-touched entry to survive eviction, got an extra backend call")
	}

	// names[1] (never refreshed) must have been evicted.
	callsBeforeEvictedCheck := backing.openCalls
	if _, err := store.Open(ctx, names[1]); err != nil {
		t.Fatalf("re-Open(%s): %v", names[1], err)
	}
	if backing.openCalls != callsBeforeEvictedCheck+1 {
		t.Fatalf("expected the untouched entry to have been evicted, got no extra backend call")
	}
}

func TestPurgePrefix_EvictsMatchingEntriesOnly(t *testing.T) {
	backing := newMockStore()
	backing.set("current/debian/dists/trixie/Release", []byte("release"))
	backing.set("current/ubuntu/dists/noble/Release", []byte("release2"))
	backing.set("2026-01-01T00-00-00/debian/dists/trixie/Release", []byte("pinned"))
	store := filecache.Wrap(backing, 1<<20)
	purger, ok := store.(filecache.Purger)
	if !ok {
		t.Fatal("expected *filecache.Store to implement filecache.Purger")
	}
	ctx := context.Background()

	for _, path := range []string{
		"current/debian/dists/trixie/Release",
		"current/ubuntu/dists/noble/Release",
		"2026-01-01T00-00-00/debian/dists/trixie/Release",
	} {
		if _, err := store.OpenPublished(ctx, path); err != nil {
			t.Fatalf("OpenPublished(%s): %v", path, err)
		}
	}
	callsAfterFill := backing.openPubCalls

	purger.PurgePrefix("current/")

	// Both "current/" entries must be gone -- re-reading them hits the backend.
	if _, err := store.OpenPublished(ctx, "current/debian/dists/trixie/Release"); err != nil {
		t.Fatalf("OpenPublished after purge: %v", err)
	}
	if _, err := store.OpenPublished(ctx, "current/ubuntu/dists/noble/Release"); err != nil {
		t.Fatalf("OpenPublished after purge: %v", err)
	}
	if backing.openPubCalls != callsAfterFill+2 {
		t.Fatalf("expected both current/ entries to be purged (2 more backend calls), got %d more",
			backing.openPubCalls-callsAfterFill)
	}

	// The pinned-snapshot entry (not under "current/") must be untouched.
	callsBeforePinnedCheck := backing.openPubCalls
	if _, err := store.OpenPublished(ctx, "2026-01-01T00-00-00/debian/dists/trixie/Release"); err != nil {
		t.Fatalf("OpenPublished: %v", err)
	}
	if backing.openPubCalls != callsBeforePinnedCheck {
		t.Fatalf("expected the non-matching entry to remain cached, got an extra backend call")
	}
}

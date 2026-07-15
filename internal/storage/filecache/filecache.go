// Package filecache provides an optional, size-bounded, in-process LRU
// cache wrapping a storage.Storage backend, so repeated requests for a
// popular file (a pool/src download, or a published dists-tree file) don't
// re-fetch it from the backend every time. Most impactful for the S3
// backend, where every miss is a real GetObject/HeadObject call; harmless
// but of little value layered over the filesystem backend, which is
// already local.
package filecache

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"strings"
	"sync"

	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/storage"
)

// maxEntryFraction bounds a single cached entry to at most 1/10th of the
// total cache size, so one large file (a huge .deb, or a big Packages
// index) can never dominate -- or on its own evict nearly all of -- the
// cache at the expense of every other popular file. A file bigger than
// this is always served straight from the backend, uncached, streamed
// through without ever being buffered into memory.
const maxEntryFraction = 10

// maxEntryAbsoluteBytes additionally caps a single cached entry regardless
// of the configured overall cache size. maxEntryFraction alone still lets a
// large storage.file_cache.size (say, tens of GB, to get a good hit rate
// over a big repo) push the per-entry budget up into multiple GB -- and
// cachedOpen buffers a cache-miss read whole via io.ReadAll before ever
// serving it, so any file under that budget, however large in absolute
// terms, gets fully read into memory first. This is what actually caused
// multi-GB RSS spikes on real downloads (a large-but-under-budget .deb),
// not just the already-guarded "bigger than the fraction" case.
const maxEntryAbsoluteBytes = 64 * 1024 * 1024 // 64 MiB

type entry struct {
	path string
	data []byte
	info storage.FileInfo
}

// Store wraps a storage.Storage, caching every read path (Open/Stat for
// pool/src files, OpenPublished/StatPublished for the published dists
// tree) by its exact path string. Every write/delete path (PutFile,
// WriteFile, Delete, DeletePublished) invalidates that exact path's cache
// entry immediately, so a caller reading back through this same Store can
// never observe stale bytes it just wrote or deleted itself -- see
// PurgePrefix for the one case that can't self-invalidate this way: a
// *different* replica rewriting "current/*" out from underneath this one.
// Everything else (ComputeChecksums, WalkPool, ListPublished*,
// ListSnapshots, ResolveSnapshot, Ping) passes straight through via the
// embedded storage.Storage, unmodified.
type Store struct {
	storage.Storage

	mu       sync.Mutex
	order    *list.List // front = most recently used
	byPath   map[string]*list.Element
	curBytes int64
	maxBytes int64
}

// Purger is implemented by storage.Storage backends that support purging
// cached entries by path prefix -- currently only *Store. Callers that
// need to invalidate stale cache entries after an out-of-band change (e.g.
// a cross-replica pub/sub notice that /current changed on another
// replica) should type-assert for this rather than requiring it
// universally; see internal/server's snapshot-published subscriber.
type Purger interface {
	PurgePrefix(prefix string)
}

// Wrap returns store unchanged if maxBytes <= 0 (the cache is disabled --
// the default), or a caching *Store around it otherwise.
func Wrap(store storage.Storage, maxBytes int64) storage.Storage {
	if maxBytes <= 0 {
		return store
	}
	return &Store{
		Storage:  store,
		order:    list.New(),
		byPath:   map[string]*list.Element{},
		maxBytes: maxBytes,
	}
}

func (s *Store) maxEntryBytes() int64 {
	limit := s.maxBytes / maxEntryFraction
	if limit > maxEntryAbsoluteBytes {
		limit = maxEntryAbsoluteBytes
	}
	return limit
}

func (s *Store) get(path string) (*entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.byPath[path]
	if !ok {
		return nil, false
	}
	s.order.MoveToFront(el)
	return el.Value.(*entry), true
}

// invalidate drops path's cache entry, if any.
func (s *Store) invalidate(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(path)
}

// removeLocked removes path's entry, if any. Caller must hold s.mu.
func (s *Store) removeLocked(path string) {
	el, ok := s.byPath[path]
	if !ok {
		return
	}
	s.curBytes -= int64(len(el.Value.(*entry).data))
	s.order.Remove(el)
	delete(s.byPath, path)
	metrics.FileCacheBytes.Set(float64(s.curBytes))
}

// PurgePrefix evicts every cached entry whose path has the given prefix.
// Used for cross-replica invalidation: a snapshot publish rewrites every
// "current/{os}/..." path in place on whichever replica ran it -- that one
// replica self-invalidates automatically (see WriteFile), but every other
// replica's independent, in-process cache has no way to know "current/"
// changed until an explicit, out-of-band purge (see internal/server's
// snapshot-published subscriber).
func (s *Store) PurgePrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var toRemove []string
	for path := range s.byPath {
		if strings.HasPrefix(path, prefix) {
			toRemove = append(toRemove, path)
		}
	}
	for _, path := range toRemove {
		s.removeLocked(path)
	}
}

// put caches data for path, evicting least-recently-used entries as needed
// to stay within maxBytes. A no-op if data alone exceeds maxEntryBytes.
func (s *Store) put(path string, data []byte, info storage.FileInfo) {
	size := int64(len(data))
	if size > s.maxEntryBytes() {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeLocked(path)
	for s.curBytes+size > s.maxBytes {
		back := s.order.Back()
		if back == nil {
			break
		}
		evicted := back.Value.(*entry)
		s.order.Remove(back)
		delete(s.byPath, evicted.path)
		s.curBytes -= int64(len(evicted.data))
		metrics.FileCacheEvictionsTotal.Inc()
	}

	el := s.order.PushFront(&entry{path: path, data: data, info: info})
	s.byPath[path] = el
	s.curBytes += size
	metrics.FileCacheBytes.Set(float64(s.curBytes))
}

// --- reads: pool/src files (FileStore) ---

func (s *Store) Exists(ctx context.Context, path string) (bool, error) {
	if _, ok := s.get(path); ok {
		metrics.FileCacheRequestsTotal.WithLabelValues("hit").Inc()
		return true, nil
	}
	return s.Storage.Exists(ctx, path)
}

func (s *Store) Stat(ctx context.Context, path string) (storage.FileInfo, error) {
	if e, ok := s.get(path); ok {
		metrics.FileCacheRequestsTotal.WithLabelValues("hit").Inc()
		return e.info, nil
	}
	metrics.FileCacheRequestsTotal.WithLabelValues("miss").Inc()
	return s.Storage.Stat(ctx, path)
}

func (s *Store) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	return s.cachedOpen(ctx, path, s.Storage.Stat, s.Storage.Open)
}

// --- reads: published dists tree (Publisher) ---

func (s *Store) StatPublished(ctx context.Context, path string) (storage.FileInfo, error) {
	if e, ok := s.get(path); ok {
		metrics.FileCacheRequestsTotal.WithLabelValues("hit").Inc()
		return e.info, nil
	}
	metrics.FileCacheRequestsTotal.WithLabelValues("miss").Inc()
	return s.Storage.StatPublished(ctx, path)
}

func (s *Store) OpenPublished(ctx context.Context, path string) (io.ReadCloser, error) {
	return s.cachedOpen(ctx, path, s.Storage.StatPublished, s.Storage.OpenPublished)
}

// cachedOpen implements Open/OpenPublished's shared cache-then-read-through
// logic, parameterized by which pair of underlying (uncached) Stat/Open
// methods to fall through to.
func (s *Store) cachedOpen(
	ctx context.Context,
	path string,
	statFn func(context.Context, string) (storage.FileInfo, error),
	openFn func(context.Context, string) (io.ReadCloser, error),
) (io.ReadCloser, error) {
	if e, ok := s.get(path); ok {
		metrics.FileCacheRequestsTotal.WithLabelValues("hit").Inc()
		return io.NopCloser(bytes.NewReader(e.data)), nil
	}
	metrics.FileCacheRequestsTotal.WithLabelValues("miss").Inc()

	// Stat first, purely to pre-screen by size: a file too large to ever
	// fit the per-entry budget is streamed straight through, never
	// buffered into memory. A Stat failure must not fall through to the
	// unconditional io.ReadAll below -- that would remove the one guard
	// against buffering an arbitrarily large file whole, precisely when
	// its size is the one thing not actually known.
	info, statErr := statFn(ctx, path)
	if statErr != nil || info.Size > s.maxEntryBytes() {
		return openFn(ctx, path)
	}

	rc, err := openFn(ctx, path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	s.put(path, data, info)
	return io.NopCloser(bytes.NewReader(data)), nil
}

// --- writes: invalidate the exact path written/deleted ---

func (s *Store) PutFile(ctx context.Context, path string, r io.Reader, size int64) error {
	err := s.Storage.PutFile(ctx, path, r, size)
	if err == nil {
		s.invalidate(path)
	}
	return err
}

func (s *Store) WriteFile(ctx context.Context, path string, r io.Reader, size int64) error {
	err := s.Storage.WriteFile(ctx, path, r, size)
	if err == nil {
		s.invalidate(path)
	}
	return err
}

func (s *Store) Delete(ctx context.Context, path string) error {
	err := s.Storage.Delete(ctx, path)
	if err == nil {
		s.invalidate(path)
	}
	return err
}

func (s *Store) DeletePublished(ctx context.Context, path string) error {
	err := s.Storage.DeletePublished(ctx, path)
	if err == nil {
		s.invalidate(path)
	}
	return err
}

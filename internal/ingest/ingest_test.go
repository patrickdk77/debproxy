package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
)

func TestExistsCacheAddHasRemove(t *testing.T) {
	c := &ExistsCache{}

	if c.Has("pool/a") {
		t.Error("Has on empty cache = true, want false")
	}

	c.Add("pool/a")
	if !c.Has("pool/a") {
		t.Error("Has after Add = false, want true")
	}

	c.Remove("pool/a")
	if c.Has("pool/a") {
		t.Error("Has after Remove = true, want false")
	}
}

// TestExistsCacheRemoveUnknownPathIsNoop is the bad-data counterpart to the
// happy-path add/remove test: Remove is called by pullThrough on every
// pull-through request, most of which never had a stale (or any) cache entry
// in the first place -- it must not panic or otherwise misbehave just
// because there was nothing to clear.
func TestExistsCacheRemoveUnknownPathIsNoop(t *testing.T) {
	c := &ExistsCache{}
	c.Remove("pool/never-added")
	if c.Has("pool/never-added") {
		t.Error("Has after removing an unknown path = true, want false")
	}
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestDigestVerifyingReaderCorrectDigestPassesThrough is the happy path: a
// stream whose content matches expectedSHA256 reads through cleanly (real
// io.EOF at the end, no error), and every byte read also lands in the
// client-side writer -- proving the tee actually tees.
func TestDigestVerifyingReaderCorrectDigestPassesThrough(t *testing.T) {
	content := []byte("the quick brown fox jumps over the lazy dog")
	var client bytes.Buffer
	dvr := newDigestVerifyingReader(bytes.NewReader(content), &client, sha256hex(content))

	got, err := io.ReadAll(dvr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("read content = %q, want %q", got, content)
	}
	if !bytes.Equal(client.Bytes(), content) {
		t.Errorf("client tee received %q, want %q", client.Bytes(), content)
	}
}

// TestDigestVerifyingReaderMismatchReturnsErrorInsteadOfEOF is the direct
// regression test for the safety property this type exists for: storage's
// own atomic write (a temp file + rename, or an all-or-nothing PUT) commits
// on a clean io.EOF and aborts/cleans up on any other error, so a corrupt
// download must surface as a real error at the point EOF would otherwise be
// returned, not silently pass through.
func TestDigestVerifyingReaderMismatchReturnsErrorInsteadOfEOF(t *testing.T) {
	content := []byte("actual upstream content")
	dvr := newDigestVerifyingReader(bytes.NewReader(content), nil, sha256hex([]byte("something else entirely")))

	_, err := io.ReadAll(dvr)
	if err == nil {
		t.Fatal("expected a digest-mismatch error, got nil (EOF passed through uncaught)")
	}
	if !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("error = %v, want it to wrap upstream.ErrDigestMismatch", err)
	}
}

// TestDigestVerifyingReaderClientWriteFailureIsBestEffort proves a broken
// client connection never aborts the underlying read -- the whole point of
// streaming to a live client is service to that client, not a precondition
// for the download that populates the cache for everyone else.
func TestDigestVerifyingReaderClientWriteFailureIsBestEffort(t *testing.T) {
	content := []byte("content that must still be fully read and hashed")
	dvr := newDigestVerifyingReader(bytes.NewReader(content), alwaysFailWriter{}, sha256hex(content))

	got, err := io.ReadAll(dvr)
	if err != nil {
		t.Fatalf("ReadAll: %v (a client write failure must not abort the read)", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("read content = %q, want %q", got, content)
	}
}

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }

// startSignalReader closes onFirstRead the moment its first Read call is
// made, before that call necessarily returns -- used below to detect the
// instant a caller begins consuming a stream, as opposed to having already
// fully drained it into memory beforehand.
type startSignalReader struct {
	r     io.Reader
	fired bool
	fire  func()
}

func (s *startSignalReader) Read(p []byte) (int, error) {
	if !s.fired {
		s.fired = true
		s.fire()
	}
	return s.r.Read(p)
}

// blockingPutStorage is a minimal storage.Storage whose PutFile signals
// putStarted on its very first Read from the reader it's given, then
// records whatever it fully reads. Every other method is an unused stub --
// Cache/CacheSourceFile touch only Exists and PutFile.
type blockingPutStorage struct {
	putStarted chan struct{}
	fireOnce   sync.Once

	mu   sync.Mutex
	data []byte
}

func newBlockingPutStorage() *blockingPutStorage {
	return &blockingPutStorage{putStarted: make(chan struct{})}
}

func (s *blockingPutStorage) Exists(context.Context, string) (bool, error) { return false, nil }

func (s *blockingPutStorage) PutFile(_ context.Context, _ string, r io.Reader, _ int64) error {
	signaled := &startSignalReader{r: r, fire: func() { s.fireOnce.Do(func() { close(s.putStarted) }) }}
	data, err := io.ReadAll(signaled)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()
	return nil
}

func (s *blockingPutStorage) storedData() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *blockingPutStorage) Open(context.Context, string) (io.ReadCloser, error) {
	return nil, storage.ErrNotImplemented
}
func (s *blockingPutStorage) Stat(context.Context, string) (storage.FileInfo, error) {
	return storage.FileInfo{}, storage.ErrNotImplemented
}
func (s *blockingPutStorage) Delete(context.Context, string) error { return storage.ErrNotImplemented }
func (s *blockingPutStorage) ComputeChecksums(context.Context, string) (model.Checksums, error) {
	return model.Checksums{}, storage.ErrNotImplemented
}
func (s *blockingPutStorage) WalkPool(context.Context, func(storage.FileInfo) error) error {
	return storage.ErrNotImplemented
}
func (s *blockingPutStorage) CleanupTempFiles(context.Context, time.Time) (int, error) {
	return 0, storage.ErrNotImplemented
}
func (s *blockingPutStorage) WriteFile(context.Context, string, io.Reader, int64) error {
	return storage.ErrNotImplemented
}
func (s *blockingPutStorage) DeletePublished(context.Context, string) error {
	return storage.ErrNotImplemented
}
func (s *blockingPutStorage) OpenPublished(context.Context, string) (io.ReadCloser, error) {
	return nil, storage.ErrNotImplemented
}
func (s *blockingPutStorage) StatPublished(context.Context, string) (storage.FileInfo, error) {
	return storage.FileInfo{}, storage.ErrNotImplemented
}
func (s *blockingPutStorage) ListPublished(context.Context, string) ([]string, error) {
	return nil, storage.ErrNotImplemented
}
func (s *blockingPutStorage) ListPublishedInfo(context.Context, string) ([]storage.FileInfo, error) {
	return nil, storage.ErrNotImplemented
}
func (s *blockingPutStorage) ListSnapshots(context.Context, string) ([]storage.SnapshotRef, error) {
	return nil, storage.ErrNotImplemented
}
func (s *blockingPutStorage) ResolveSnapshot(context.Context, string, time.Time) (string, error) {
	return "", storage.ErrNotImplemented
}
func (s *blockingPutStorage) Ping(context.Context) error { return nil }

// stubIndex is a minimal metadata.MetadataIndex: Cache/CacheSourceFile only
// ever call UpsertEntry (via upsertEntry), which just needs to succeed.
type stubIndex struct{}

func (stubIndex) Ping(context.Context) error                          { return nil }
func (stubIndex) Migrate(context.Context) error                       { return nil }
func (stubIndex) Reset(context.Context) error                         { return nil }
func (stubIndex) Refresh(context.Context) error                       { return nil }
func (stubIndex) Flush(context.Context) error                         { return nil }
func (stubIndex) UpsertEntry(context.Context, model.IndexEntry) error { return nil }
func (stubIndex) RemoveEntry(context.Context, model.IndexEntry) error { return nil }
func (stubIndex) ListEntries(context.Context, model.Selector) ([]model.IndexEntry, error) {
	return nil, nil
}
func (stubIndex) EntryByDigest(context.Context, model.Digest) (*model.IndexEntry, error) {
	return nil, nil
}
func (stubIndex) FindEntry(context.Context, model.Selector, string, string) (*model.IndexEntry, error) {
	return nil, nil
}
func (stubIndex) UpsertUpstreamState(context.Context, model.UpstreamPackageState) error { return nil }
func (stubIndex) GetUpstreamState(context.Context, string, string, string) (*model.UpstreamPackageState, error) {
	return nil, nil
}
func (stubIndex) UpsertSourceEntry(context.Context, model.SourceEntry) error { return nil }
func (stubIndex) RemoveSourceEntry(context.Context, model.SourceEntry) error { return nil }
func (stubIndex) ListSourceEntries(context.Context, model.Selector) ([]model.SourceEntry, error) {
	return nil, nil
}
func (stubIndex) FindSourceEntry(context.Context, model.Selector, string, string) (*model.SourceEntry, error) {
	return nil, nil
}

// TestCacheStreamsIntoStorageWithoutBufferingWholeFile is the direct
// regression test for this session's memory-spike finding: Cache used to
// call upstream.Fetcher.DownloadDeb, which read the *entire* upstream
// response into a []byte before ever calling storage.PutFile -- so nothing
// reached storage until the whole download had already finished. Cache now
// delegates to CacheStreaming(..., nil), which tees the live response
// straight into PutFile as bytes arrive. Proven here by an upstream that
// sends half its response, blocks, then sends the rest: PutFile must begin
// reading (proven via a signal on its very first Read) before the second
// half is ever released -- something categorically impossible if the whole
// body had to be read into memory first.
func TestCacheStreamsIntoStorageWithoutBufferingWholeFile(t *testing.T) {
	content := bytes.Repeat([]byte("streamed-not-buffered-"), 4096) // a few hundred KB
	half := len(content) / 2
	releaseSecondHalf := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSecondHalf) }) }
	const debPath = "pool/main/h/hello/hello_1.0_amd64.deb"

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+debPath {
			http.NotFound(w, r)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("httptest ResponseWriter does not support Flush")
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(content[:half]); err != nil {
			t.Errorf("write first half: %v", err)
			return
		}
		flusher.Flush()
		<-releaseSecondHalf
		_, _ = w.Write(content[half:])
	}))
	defer upstreamSrv.Close()
	// Registered after upstreamSrv's own Close defer, so it runs first
	// (defers unwind LIFO): however this test exits -- pass, fail, or a
	// t.Fatal partway through -- the handler goroutine must be unblocked
	// before Close() waits on it, or Close() hangs forever.
	defer release()

	store := newBlockingPutStorage()
	in := New(store, stubIndex{}, nil, nil, nil)

	pkg := avail.Pkg{
		Name:     "hello",
		Version:  "1.0",
		Filename: debPath,
		SHA256:   sha256hex(content),
		Size:     int64(len(content)),
		PoolPath: debPath,
		Upstream: model.UpstreamSource{Name: "test-upstream", URL: upstreamSrv.URL},
	}

	cacheDone := make(chan error, 1)
	go func() {
		cacheDone <- in.Cache(context.Background(), "debian", "trixie", pkg, false)
	}()

	select {
	case <-store.putStarted:
		// Storage began reading before the second half was released -- proves
		// streaming, not full buffering.
	case err := <-cacheDone:
		t.Fatalf("Cache returned (err=%v) before PutFile ever started reading -- and before the upstream even finished responding; something is very wrong", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PutFile to start reading -- Cache is buffering the whole response before writing to storage")
	}

	release()

	select {
	case err := <-cacheDone:
		if err != nil {
			t.Fatalf("Cache: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Cache to finish after releasing the second half")
	}

	if !bytes.Equal(store.storedData(), content) {
		t.Fatal("stored content does not match what upstream sent")
	}
}

// Package ingest downloads, verifies, stores, and indexes upstream packages.
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/webhook"
)

// ExistsCache is a persistent in-memory set of pool paths known to exist in
// storage. Under normal operation pool files are never deleted, so a positive
// hit remains valid indefinitely and S3/filesystem Exists checks can be
// skipped on subsequent Cache calls for the same path. That assumption can be
// violated out-of-band (a GC bug, a manual purge) -- see Remove, which lets a
// caller that has independently proven a path no longer exists correct a
// stale positive rather than have Cache trust it forever.
type ExistsCache struct {
	m sync.Map
}

func (c *ExistsCache) Has(path string) bool {
	_, ok := c.m.Load(path)
	return ok
}

func (c *ExistsCache) Add(path string) {
	c.m.Store(path, struct{}{})
}

// Remove clears any positive entry for path, forcing the next Cache call for
// it to re-verify against real storage instead of trusting a stale hit.
func (c *ExistsCache) Remove(path string) {
	c.m.Delete(path)
}

// Ingestor caches packages into the pool and records index entries.
type Ingestor struct {
	store    storage.Storage
	index    metadata.MetadataIndex
	client   *http.Client
	notifier *webhook.Notifier
	exists   *ExistsCache // optional; nil disables caching
}

// New returns an Ingestor. notifier and exists may be nil.
func New(store storage.Storage, index metadata.MetadataIndex, client *http.Client, notifier *webhook.Notifier, exists *ExistsCache) *Ingestor {
	return &Ingestor{store: store, index: index, client: client, notifier: notifier, exists: exists}
}

// Cache ensures the package's .deb is in the pool (downloading and verifying if
// needed) and records its index entry. It is idempotent. notify controls
// whether a freshly-downloaded package fires a webhook event: callers
// downloading a whole dependency closure (Syncer.Prime, and pull-through) want
// every real download notified, but Syncer.runUpdate's auto_update pass wants
// only the top-level package whose newer version triggered the update to
// notify -- a dependency pulled in solely to satisfy that package's
// requirements isn't itself a separate update worth notifying about.
func (in *Ingestor) Cache(ctx context.Context, osName, codename string, p avail.Pkg, notify bool) error {
	if in.exists == nil || !in.exists.Has(p.PoolPath) {
		exists, err := in.store.Exists(ctx, p.PoolPath)
		if err != nil {
			return err
		}
		if !exists {
			slog.Debug("downloading package", "package", p.Name, "version", p.Version, "upstream", p.Upstream.Name)
			f := upstream.NewFetcher(p.Upstream, in.client)
			data, err := f.DownloadDeb(ctx, p.Filename, p.SHA256)
			if err != nil {
				return err
			}
			if err := in.store.PutFile(ctx, p.PoolPath, bytes.NewReader(data), int64(len(data))); err != nil {
				return err
			}
			in.onDownloaded(osName, codename, p, notify)
		}
		if in.exists != nil {
			in.exists.Add(p.PoolPath)
		}
	}

	return in.upsertEntry(ctx, osName, codename, p)
}

// CacheStreaming is like Cache but, for the not-yet-cached case, streams the
// download directly into w as bytes arrive from upstream instead of
// buffering the whole file in memory first -- used when a live client
// request triggered this fetch (see Server.pullThroughStream), so the client
// sees bytes flowing immediately instead of a completely silent connection
// for the whole fetch, and large files never sit fully resident in memory.
// w may be nil (equivalent to Cache, just via the streaming download path).
//
// A write to w that fails (e.g. the client disconnects) is best-effort only
// and never aborts the fetch -- the point of streaming to a live client is
// service to that client, not a precondition for populating the cache other
// requests will benefit from. Digest verification happens as bytes are
// copied through into storage: see digestVerifyingReader for how a mismatch
// is turned into a real Read error so storage's own atomic write (temp file
// + rename, or an all-or-nothing PUT) never commits a corrupt download.
func (in *Ingestor) CacheStreaming(ctx context.Context, osName, codename string, p avail.Pkg, notify bool, w io.Writer) error {
	if in.exists == nil || !in.exists.Has(p.PoolPath) {
		exists, err := in.store.Exists(ctx, p.PoolPath)
		if err != nil {
			return err
		}
		if !exists {
			slog.Debug("downloading package", "package", p.Name, "version", p.Version, "upstream", p.Upstream.Name)
			f := upstream.NewFetcher(p.Upstream, in.client)
			body, err := f.FetchDebStream(ctx, p.Filename)
			if err != nil {
				return err
			}
			defer body.Close()
			return in.CacheStreamingBody(ctx, osName, codename, p, body, notify, w)
		}
		if in.exists != nil {
			in.exists.Add(p.PoolPath)
		}
	}

	return in.upsertEntry(ctx, osName, codename, p)
}

// CacheStreamingBody is CacheStreaming's second half, factored out for
// callers that need to confirm upstream actually responded before committing
// to anything client-visible (see Server.pullThroughStream, which sends
// response headers only after its own call to upstream.Fetcher.FetchDebStream
// succeeds, so an unreachable upstream still gets a normal error response
// instead of a stream that never starts). body is the already-open,
// already-200-confirmed upstream response; the caller owns closing it.
func (in *Ingestor) CacheStreamingBody(ctx context.Context, osName, codename string, p avail.Pkg, body io.Reader, notify bool, w io.Writer) error {
	dvr := newDigestVerifyingReader(body, w, p.SHA256)
	if err := in.store.PutFile(ctx, p.PoolPath, dvr, p.Size); err != nil {
		return err
	}
	in.onDownloaded(osName, codename, p, notify)
	if in.exists != nil {
		in.exists.Add(p.PoolPath)
	}
	return in.upsertEntry(ctx, osName, codename, p)
}

// onDownloaded logs and records metrics/webhook for a package that was just
// freshly downloaded, shared by Cache and CacheStreaming.
func (in *Ingestor) onDownloaded(osName, codename string, p avail.Pkg, notify bool) {
	slog.Info("cached package", "package", p.Name, "version", p.Version, "upstream", p.Upstream.Name, "path", p.PoolPath)
	if p.Upstream.AutoUpdate {
		metrics.AutoUpdateFilesTotal.WithLabelValues(osName, codename, p.Upstream.Name).Inc()
	}
	if notify {
		in.notifier.Fire(webhook.Event{
			Package:   p.Name,
			Version:   p.Version,
			Arch:      p.Arch,
			OS:        osName,
			Codename:  codename,
			Component: p.Component,
			Section:   p.Section,
			Upstream:  p.Upstream.Name,
			PoolPath:  p.PoolPath,
			Size:      p.Size,
		})
	}
}

// upsertEntry records p's index entry, shared by Cache and CacheStreaming.
func (in *Ingestor) upsertEntry(ctx context.Context, osName, codename string, p avail.Pkg) error {
	entry := model.IndexEntry{
		OS:             osName,
		Codename:       codename,
		Component:      p.Component,
		Arch:           p.Arch,
		Package:        p.Name,
		Version:        p.Version,
		Upstream:       p.Upstream.Name,
		FromAutoUpdate: p.Upstream.AutoUpdate,
		PoolPath:       p.PoolPath,
		Checksums: model.Checksums{
			SHA256: model.Digest(p.SHA256),
			SHA512: model.Digest(p.SHA512),
		},
		Size:      p.Size,
		Control:   p.StanzaStr,
		FirstSeen: metadata.Now(),
	}
	return in.index.UpsertEntry(ctx, entry)
}

// digestVerifyingReader wraps an upstream response body, tee-ing bytes to an
// optional client writer (best-effort: a write failure there -- the client
// disconnecting mid-stream -- never aborts the read; only the copy into
// storage matters for the cache to be usefully populated for the next
// request) while computing a running SHA256. On EOF it substitutes
// upstream.ErrDigestMismatch for io.EOF if the accumulated hash doesn't match
// expectedSHA256, so the storage backend's own atomic write (a temp file +
// rename for the filesystem backend, or an all-or-nothing PUT for S3) never
// commits a corrupt download to the canonical pool path -- io.Copy (used
// internally by every Storage.PutFile implementation) treats any non-EOF
// Read error as fatal and aborts/cleans up rather than finishing the write.
// flusher matches http.Flusher's shape structurally (without importing
// net/http just for this): an http.ResponseWriter passed in as client
// satisfies it automatically. Without flushing after every tee'd write, the
// bytes just sit in Go's internal per-response buffer until enough
// accumulates (or the handler returns) to trigger an automatic flush --
// silently defeating real-time streaming to the client for small-to-medium
// writes, which is the entire point of tee-ing in the first place.
type flusher interface {
	Flush()
}

type digestVerifyingReader struct {
	src            io.Reader
	client         io.Writer // may be nil
	clientFlush    flusher   // may be nil (client doesn't support it, or client is nil)
	clientOK       bool
	hash           hash.Hash
	expectedSHA256 string
}

func newDigestVerifyingReader(src io.Reader, client io.Writer, expectedSHA256 string) *digestVerifyingReader {
	f, _ := client.(flusher)
	return &digestVerifyingReader{
		src:            src,
		client:         client,
		clientFlush:    f,
		clientOK:       client != nil,
		hash:           sha256.New(),
		expectedSHA256: expectedSHA256,
	}
}

func (d *digestVerifyingReader) Read(p []byte) (int, error) {
	n, err := d.src.Read(p)
	if n > 0 {
		d.hash.Write(p[:n]) // hash.Hash.Write never returns an error
		if d.clientOK {
			if _, werr := d.client.Write(p[:n]); werr != nil {
				// Best-effort only: stop trying to write to a broken client
				// connection, but keep reading/hashing/caching regardless.
				d.clientOK = false
			} else if d.clientFlush != nil {
				d.clientFlush.Flush()
			}
		}
	}
	if err == io.EOF {
		got := hex.EncodeToString(d.hash.Sum(nil))
		if !strings.EqualFold(got, d.expectedSHA256) {
			return n, fmt.Errorf("%w: got %s want %s", upstream.ErrDigestMismatch, got, d.expectedSHA256)
		}
	}
	return n, err
}

// CacheSourceFile downloads one source package file from the upstream and
// stores it under src/. It is idempotent: if the file is already present it
// returns immediately without verifying the content.
func (in *Ingestor) CacheSourceFile(ctx context.Context, entry model.SourceEntry, us model.UpstreamSource, filename string) error {
	var srcFile *model.SourceFile
	for i := range entry.Files {
		if entry.Files[i].Filename == filename {
			srcFile = &entry.Files[i]
			break
		}
	}
	if srcFile == nil {
		return fmt.Errorf("file %s not listed in source entry %s %s", filename, entry.Package, entry.Version)
	}

	filePath := model.SourceFilePath(entry.OS, entry.Codename, entry.Upstream, entry.Component, entry.Package, filename)

	if in.exists != nil && in.exists.Has(filePath) {
		return nil
	}
	exists, err := in.store.Exists(ctx, filePath)
	if err != nil {
		return err
	}
	if exists {
		if in.exists != nil {
			in.exists.Add(filePath)
		}
		return nil
	}

	slog.Debug("downloading source file", "package", entry.Package, "version", entry.Version, "file", filename, "upstream", entry.Upstream)
	f := upstream.NewFetcher(us, in.client)
	data, err := f.DownloadSourceFile(ctx, entry.UpstreamDir, filename, string(srcFile.SHA256))
	if err != nil {
		return err
	}
	if err := in.store.PutFile(ctx, filePath, bytes.NewReader(data), int64(len(data))); err != nil {
		return err
	}
	slog.Info("cached source file", "package", entry.Package, "version", entry.Version, "file", filename, "upstream", entry.Upstream)
	if in.exists != nil {
		in.exists.Add(filePath)
	}
	if us.AutoUpdate {
		metrics.AutoUpdateSourceFilesTotal.WithLabelValues(entry.OS, entry.Codename, entry.Upstream).Inc()
	}
	return nil
}

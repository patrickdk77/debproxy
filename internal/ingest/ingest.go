// Package ingest downloads, verifies, stores, and indexes upstream packages.
package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/debproxy/debproxy/internal/apt"
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
//
// Equivalent to CacheStreaming with a nil w (see its doc comment): every
// caller here (Prime's and auto-update's dependency-closure downloads, and
// pull-through's Range-request-on-miss and re-index paths, none of which
// have a live client response to tee bytes into) used to instead go through
// upstream.Fetcher.DownloadDeb, which read the whole .deb into a []byte
// before ever writing to storage -- fully resident in memory regardless of
// file size. Real multi-GB packages made that a real memory spike; this
// still ends up cached and indexed identically, just via the same bounded,
// streamed write CacheStreaming already uses for the live pull-through path.
func (in *Ingestor) Cache(ctx context.Context, osName, codename string, p avail.Pkg, notify bool) error {
	return in.CacheStreaming(ctx, osName, codename, p, notify, nil)
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
	dvr := newDigestVerifyingReader(body, w, p.Hashes())
	if err := in.store.PutFile(ctx, p.PoolPath, dvr, p.Size); err != nil {
		return err
	}
	if dvr.read == 0 {
		// The backend answered success without reading a byte, which the
		// filesystem store does when another request already landed this
		// file. The caller has already sent a 200 with a Content-Length,
		// so the client is waiting on exactly that many bytes and would
		// otherwise get none. Serve the stored copy to it instead. No
		// download happened, so the freshly-cached log, metric and
		// webhook stay silent.
		if w != nil {
			rc, err := in.store.Open(ctx, p.PoolPath)
			if err != nil {
				return fmt.Errorf("open already-cached %s: %w", p.PoolPath, err)
			}
			defer rc.Close()
			if _, err := io.Copy(w, rc); err != nil {
				return fmt.Errorf("serve already-cached %s: %w", p.PoolPath, err)
			}
		}
	} else {
		in.onDownloaded(osName, codename, p, notify)
	}
	if in.exists != nil {
		in.exists.Add(p.PoolPath)
	}
	if dvr.read == 0 {
		return in.upsertEntry(ctx, osName, codename, p)
	}
	return in.upsertEntryWith(ctx, osName, codename, p, dvr.checksums())
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
	cs := model.Checksums{SHA256: model.Digest(p.SHA256), SHA512: model.Digest(p.SHA512)}
	if cs.SHA256 == "" {
		computed, err := in.store.ComputeChecksums(ctx, p.PoolPath)
		if err != nil {
			return fmt.Errorf("compute checksums for %s: %w", p.PoolPath, err)
		}
		cs = computed
	}
	return in.upsertEntryWith(ctx, osName, codename, p, cs)
}

func (in *Ingestor) upsertEntryWith(ctx context.Context, osName, codename string, p avail.Pkg, cs model.Checksums) error {
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
		Checksums:      cs,
		Size:           p.Size,
		Control:        p.StanzaStr,
		FirstSeen:      metadata.Now(),
	}
	return in.index.UpsertEntry(ctx, entry)
}

// digestVerifyingReader wraps an upstream response body, tee-ing bytes to an
// optional client writer while hashing them. At io.EOF the strongest digest
// the upstream published for the file (apt.Hashes.Best) is compared with
// what was read, and a mismatch comes back in place of io.EOF so the storage
// write fails and nothing corrupt is kept. SHA256 and SHA512 are computed
// alongside whichever algorithm verifies, because they are what debproxy
// publishes for the file afterwards.
//
// Client writes are best-effort: a failed write marks the client as gone and
// the stream continues to storage, so one disconnected client does not
// waste the download.
type flusher interface {
	Flush()
}

type digestVerifyingReader struct {
	src         io.Reader
	client      io.Writer // may be nil
	clientFlush flusher   // may be nil (client doesn't support it, or client is nil)
	clientOK    bool
	algo        apt.HashAlgo
	expected    string
	check       hash.Hash // hasher for algo when it is neither SHA256 nor SHA512
	h256        hash.Hash
	h512        hash.Hash
	read        int64
}

func newDigestVerifyingReader(src io.Reader, client io.Writer, expected apt.Hashes) *digestVerifyingReader {
	f, _ := client.(flusher)
	d := &digestVerifyingReader{
		src:         src,
		client:      client,
		clientFlush: f,
		clientOK:    client != nil,
		h256:        sha256.New(),
		h512:        sha512.New(),
	}
	d.algo, d.expected = expected.Best()
	switch d.algo {
	case apt.HashSHA256, apt.HashSHA512, "":
	default:
		d.check = apt.NewHash(d.algo)
	}
	return d
}

func (d *digestVerifyingReader) Read(p []byte) (int, error) {
	n, err := d.src.Read(p)
	if n > 0 {
		d.read += int64(n)
		d.h256.Write(p[:n]) // hash.Hash.Write never returns an error
		d.h512.Write(p[:n])
		if d.check != nil {
			d.check.Write(p[:n])
		}
		if d.clientOK {
			if _, werr := d.client.Write(p[:n]); werr != nil {
				d.clientOK = false
			} else if d.clientFlush != nil {
				d.clientFlush.Flush()
			}
		}
	}
	if err == io.EOF {
		if d.expected == "" {
			return n, apt.ErrNoDigest
		}
		got := d.got()
		if !strings.EqualFold(got, d.expected) {
			return n, fmt.Errorf("%w: %s got %s want %s", upstream.ErrDigestMismatch, d.algo, got, d.expected)
		}
	}
	return n, err
}

func (d *digestVerifyingReader) got() string {
	switch d.algo {
	case apt.HashSHA256:
		return hex.EncodeToString(d.h256.Sum(nil))
	case apt.HashSHA512:
		return hex.EncodeToString(d.h512.Sum(nil))
	}
	return hex.EncodeToString(d.check.Sum(nil))
}

// checksums is meaningful once the stream has been read to EOF.
func (d *digestVerifyingReader) checksums() model.Checksums {
	return model.Checksums{
		SHA256: model.Digest(hex.EncodeToString(d.h256.Sum(nil))),
		SHA512: model.Digest(hex.EncodeToString(d.h512.Sum(nil))),
	}
}

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
	body, err := f.FetchSourceFileStream(ctx, entry.UpstreamDir, filename)
	if err != nil {
		return err
	}
	defer body.Close()
	dvr := newDigestVerifyingReader(body, nil, srcFile.Hashes())
	if err := in.store.PutFile(ctx, filePath, dvr, srcFile.Size); err != nil {
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

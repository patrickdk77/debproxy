// Package server exposes the apt repository over HTTP: static signed snapshots
// (/current, /{date}, /{snapshot-id}), a dynamic /live view of upstream plus
// cache, the global pool with lazy pull-through, and the published signing keys.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/ingest"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/webhook"
)

// Server handles all repository HTTP requests.
type Server struct {
	cfg        *config.Config
	store      storage.Storage
	index      metadata.MetadataIndex
	key        *signing.Key
	client     *http.Client
	indexCache *upstream.IndexCache
	notifier   *webhook.Notifier
	exists     *ingest.ExistsCache // shared with syncer; nil disables re-index

	mu           sync.Mutex
	liveCache    map[string]*liveEntry   // key: os/codename
	liveBuilding map[string]chan struct{} // in-flight builds
	retryCancel  map[string]context.CancelFunc // background mismatch retries
}

const (
	liveTTLBase   = 12 * time.Minute
	liveTTLJitter = 5 * time.Minute
)

var errUnknownSelector = errors.New("unknown snapshot selector")

type liveEntry struct {
	av     *avail.Available
	files  map[string][]byte
	hashes map[string]string // file key -> sha256 from Release; O(1) ETag lookup
	built  time.Time
	expiry time.Time
}

// New creates a Server. notifier and exists may be nil.
// exists should be the same ExistsCache used by the Syncer so that pull-through
// re-indexing and update operations share a consistent view of indexed files.
func New(cfg *config.Config, store storage.Storage, index metadata.MetadataIndex, key *signing.Key, client *http.Client, indexCache *upstream.IndexCache, notifier *webhook.Notifier, exists *ingest.ExistsCache) *Server {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if indexCache == nil {
		indexCache = upstream.NewIndexCache()
	}
	return &Server{
		cfg:          cfg,
		store:        store,
		index:        index,
		key:          key,
		client:       client,
		indexCache:   indexCache,
		notifier:     notifier,
		exists:       exists,
		liveCache:    map[string]*liveEntry{},
		liveBuilding: map[string]chan struct{}{},
		retryCancel:  map[string]context.CancelFunc{},
	}
}

// sweepExpiredLiveCache removes entries whose TTL has elapsed so that inactive
// os/codename combinations don't hold large index byte slices indefinitely.
// Must be called with s.mu held.
func (s *Server) sweepExpiredLiveCache(now time.Time) {
	for k, e := range s.liveCache {
		if now.After(e.expiry) {
			delete(s.liveCache, k)
		}
	}
}

// Handler returns the HTTP handler with logging, response compression, and metrics.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.route)

	var h http.Handler = mux
	h = compress(h)
	h = logging(h)
	h = metricsMiddleware(h)
	return h
}

// selectorType returns "live", "current", or "snapshot" from the first URL path segment.
// r.URL.Path is already cleaned by net/http before reaching ServeHTTP.
func selectorType(urlPath string) string {
	s := strings.TrimPrefix(urlPath, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "live":
		return "live"
	case "current":
		return "current"
	default:
		return "snapshot"
	}
}

// metricsMiddleware records per-request counters and latency histograms.
// It skips /healthz to avoid polluting metrics with health-check noise.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		sel := selectorType(r.URL.Path)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		elapsed := time.Since(start).Seconds()
		metrics.HTTPRequestsTotal.WithLabelValues(sel, strconv.Itoa(sw.status)).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(sel).Observe(elapsed)
	})
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ua := r.UserAgent(); ua != "" {
		r = r.WithContext(upstream.WithUserAgent(r.Context(), ua))
	}
	clean := strings.Trim(path.Clean("/"+r.URL.Path), "/")
	if clean == "" {
		http.Error(w, "debproxy", http.StatusOK)
		return
	}
	parts := strings.Split(clean, "/")
	switch parts[0] {
	case "keys":
		s.servePublished(w, r, clean)
	case "live":
		s.handleLive(w, r, parts[1:])
	default:
		s.handleSnapshot(w, r, parts)
	}
}

// handleSnapshot serves /{selector}/{os}/{remainder...}.
func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	selector, osName := parts[0], parts[1]
	remainder := parts[2:]

	snapshotID, err := s.resolveSnapshot(r.Context(), osName, selector)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, errUnknownSelector) {
			http.NotFound(w, r)
			return
		}
		slog.Warn("resolve snapshot failed", "os", osName, "selector", selector, "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	if remainder[0] == "pool" {
		// remainder: [pool, os, codename, upstream, ...]
		cn, up := segAt(remainder, 2), segAt(remainder, 3)
		s.servePool(w, r, strings.Join(remainder, "/"), false, osName, cn, up)
		return
	}
	if remainder[0] == "src" {
		// Source files under snapshots are served directly from storage (no pull-through).
		// remainder: [src, codename, upstream, ...]
		cn, up := segAt(remainder, 1), segAt(remainder, 2)
		s.servePool(w, r, strings.Join(remainder, "/"), false, osName, cn, up)
		return
	}
	rel := path.Join(snapshotID, osName, path.Join(remainder...))
	s.servePublished(w, r, rel)
}

// handleLive serves /live/{os}/{remainder...} with dynamic generation and
// pull-through.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request, rest []string) {
	if len(rest) < 2 {
		http.NotFound(w, r)
		return
	}
	osName := rest[0]
	remainder := rest[1:]

	if remainder[0] == "pool" {
		// remainder: [pool, os, codename, upstream, ...]
		cn, up := segAt(remainder, 2), segAt(remainder, 3)
		s.servePool(w, r, strings.Join(remainder, "/"), true, osName, cn, up)
		return
	}
	if remainder[0] == "src" {
		codename := ""
		if len(remainder) > 1 {
			codename = remainder[1]
		}
		s.serveSrc(w, r, osName, codename, strings.Join(remainder, "/"))
		return
	}
	if remainder[0] == "dists" {
		if len(remainder) < 3 {
			http.NotFound(w, r)
			return
		}
		codename := remainder[1]
		entry, err := s.getLive(r.Context(), osName, codename)
		if err != nil {
			if r.Context().Err() != nil {
				slog.Debug("client disconnected waiting for live build",
					"os", osName, "codename", codename, "path", path.Join(remainder...))
				return
			}
			slog.Error("live generation failed", "os", osName, "codename", codename,
				"path", path.Join(remainder...), "err", err)
			http.Error(w, "live generation failed", http.StatusBadGateway)
			return
		}
		key := path.Join(remainder...)
		data, ok := entry.files[key]
		if !ok {
			// Plain index file (Packages/Sources) is never stored  -- serve from
			// a compressed variant, transparently decoding if the client can't
			// accept any of our compressed formats.
			s.servePlainFromLive(w, r, key, entry)
			return
		}
		serveBytes(w, r, key, data, entry.built)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) resolveSnapshot(ctx context.Context, osName, selector string) (string, error) {
	if selector == "current" {
		return "current", nil
	}
	refs, err := s.store.ListSnapshots(ctx, osName)
	if err != nil {
		return "", err
	}
	for _, ref := range refs {
		if ref.ID == selector {
			return selector, nil
		}
	}
	if t, err := time.Parse("2006-01-02", selector); err == nil {
		return s.store.ResolveSnapshot(ctx, osName, t.Add(24*time.Hour-time.Second))
	}
	if t, err := time.Parse("2006-01-02T15-04-05", selector); err == nil {
		return s.store.ResolveSnapshot(ctx, osName, t)
	}
	return "", errUnknownSelector
}

func (s *Server) servePublished(w http.ResponseWriter, r *http.Request, relPath string) {
	info, err := s.store.StatPublished(r.Context(), relPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Plain index files are not stored  -- serve from a compressed variant.
			s.servePublishedFromCompressed(w, r, relPath)
			return
		}
		slog.Error("stat published file", "path", relPath, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rc, err := s.store.OpenPublished(r.Context(), relPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		slog.Error("open published file", "path", relPath, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	serveSeekable(w, r, relPath, rc, info.Size, info.ModTime)
}

// servePublishedFromCompressed serves a plain (unencoded) file by reading a
// compressed variant from storage. Plain Packages/Sources files are never
// stored  -- only compressed variants exist.
//
// The ETag is the sha256 of the plain file as recorded in the Release document
// stored alongside the snapshot. Because it is the content hash (not a hash of
// a particular encoding), it is consistent across gzip/zstd passthrough and
// decompressed responses, making If-None-Match work regardless of encoding.
func (s *Server) servePublishedFromCompressed(w http.ResponseWriter, r *http.Request, relPath string) {
	accept := r.Header.Get("Accept-Encoding")

	// Always read from a fixed canonical order so the ETag (sha256 of the bytes
	// we read) is stable regardless of what encoding the client accepts.
	var compBytes []byte
	var compSfx string
	for _, sfx := range []string{".zst", ".gz", ".xz"} {
		rc, err := s.store.OpenPublished(r.Context(), relPath+sfx)
		if err != nil {
			continue
		}
		b, rerr := io.ReadAll(rc)
		rc.Close()
		if rerr != nil {
			slog.Warn("read compressed published index", "path", relPath+sfx, "err", rerr)
			continue
		}
		compBytes = b
		compSfx = sfx
		break
	}
	if compBytes == nil {
		http.NotFound(w, r)
		return
	}

	// ETag: sha256 of the canonical compressed bytes we already have in memory.
	// Using a fixed read order (zst -> gz -> xz) ensures the same variant is
	// always chosen, so the ETag is stable across requests regardless of what
	// encoding the client accepts.
	compHash := sha256.Sum256(compBytes)
	etag := fmt.Sprintf(`%x`, compHash)

	// Decide whether to pass through compressed or decompress.
	var body []byte
	var encoding string
	switch {
	case compSfx == ".zst" && strings.Contains(accept, "zstd"):
		encoding, body = "zstd", compBytes
	case compSfx == ".gz" && strings.Contains(accept, "gzip"):
		encoding, body = "gzip", compBytes
	case strings.Contains(accept, "gzip"):
		// Canonical was .zst but client only accepts gzip  -- try a second read
		// for the .gz variant so we avoid sending plain bytes unnecessarily.
		if rc, err := s.store.OpenPublished(r.Context(), relPath+".gz"); err == nil {
			if b, rerr := io.ReadAll(rc); rerr == nil {
				encoding, body = "gzip", b
			} else {
				slog.Warn("read gz published index for passthrough", "path", relPath+".gz", "err", rerr)
			}
			rc.Close()
		}
		if body == nil {
			plain, err := decompressBytes(compSfx, compBytes)
			if err != nil {
				slog.Warn("decompress published index for plain serve", "path", relPath, "suffix", compSfx, "err", err)
				http.Error(w, "decompress failed", http.StatusInternalServerError)
				return
			}
			body = plain
		}
	default:
		plain, err := decompressBytes(compSfx, compBytes)
		if err != nil {
			slog.Warn("decompress published index for plain serve", "path", relPath, "suffix", compSfx, "err", err)
			http.Error(w, "decompress failed", http.StatusInternalServerError)
			return
		}
		body = plain
	}

	w.Header().Set("Cache-Control", httpCacheControl(r.URL.Path))
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("Content-Type", contentType(relPath))
	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	// http.ServeContent reads the ETag we set above, handles If-None-Match and
	// range requests, and does not override the ETag header.
	http.ServeContent(w, r, path.Base(relPath), time.Time{}, bytes.NewReader(body))
}

// segAt returns segs[i] or "" if i is out of range.
func segAt(segs []string, i int) string {
	if i < len(segs) {
		return segs[i]
	}
	return ""
}

// servePool serves a pool .deb, pulling it (and its dependency closure) through
// from upstream on first request when allowPullThrough is set.
// osLabel, cnLabel, upLabel are the metric label values passed by the caller
// from already-parsed URL segments  -- no re-parsing needed.
func (s *Server) servePool(w http.ResponseWriter, r *http.Request, poolPath string, allowPullThrough bool, osLabel, cnLabel, upLabel string) {
	exists, err := s.store.Exists(r.Context(), poolPath)
	if err != nil {
		slog.Error("pool exists check", "path", poolPath, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		if !allowPullThrough {
			http.NotFound(w, r)
			return
		}
		if err := s.pullThrough(r.Context(), poolPath); err != nil {
			slog.Error("pull-through", "path", poolPath, "err", err)
			http.Error(w, "pull-through failed", http.StatusBadGateway)
			metrics.PullThroughsTotal.WithLabelValues(osLabel, cnLabel, upLabel, "error").Inc()
			return
		}
		metrics.PullThroughsTotal.WithLabelValues(osLabel, cnLabel, upLabel, "success").Inc()
	} else {
		metrics.PoolHitsTotal.WithLabelValues(osLabel, cnLabel, upLabel).Inc()
		// File is in the pool but absent from the metadata index  -- e.g. a
		// prior `debproxy prime` or `debproxy update` downloaded it without
		// flushing, so the pool file outlived the process that wrote it.
		// Re-establish the metadata entry so the next snapshot includes it.
		if allowPullThrough && s.exists != nil && !s.exists.Has(poolPath) {
			if err := s.pullThrough(r.Context(), poolPath); err != nil {
				slog.Warn("re-index pull-through", "path", poolPath, "err", err)
				// Non-fatal: the file exists and will be served; metadata will
				// be repaired by `debproxy rebuild` if this keeps failing.
			}
		}
	}

	info, err := s.store.Stat(r.Context(), poolPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		slog.Error("pool stat", "path", poolPath, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rc, err := s.store.Open(r.Context(), poolPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		slog.Error("pool open", "path", poolPath, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	serveSeekable(w, r, poolPath, rc, info.Size, info.ModTime)
}

// serveSrc serves a source package file from src/, pulling it through from
// upstream on first request when called from the live path.
func (s *Server) serveSrc(w http.ResponseWriter, r *http.Request, osName, codename, srcPath string) {
	// Ensure the file exists locally, pulling through from upstream if needed.
	exists, err := s.store.Exists(r.Context(), srcPath)
	if err != nil {
		slog.Error("src exists check", "path", srcPath, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		slog.Debug("source pull-through", "path", srcPath)
		if err := s.pullThroughSource(r.Context(), osName, srcPath); err != nil {
			slog.Error("source pull-through failed", "path", srcPath, "err", err)
			http.Error(w, "source pull-through failed", http.StatusBadGateway)
			metrics.SourcePullThroughsTotal.WithLabelValues(osName, codename, "error").Inc()
			return
		}
		metrics.SourcePullThroughsTotal.WithLabelValues(osName, codename, "success").Inc()
	}

	info, err := s.store.Stat(r.Context(), srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rc, err := s.store.Open(r.Context(), srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	serveSeekable(w, r, srcPath, rc, info.Size, info.ModTime)
}

// pullThroughSource fetches one source file from the upstream and stores it.
// srcPath has the form src/{os}/{codename}/{upstream}/{component}/{letter}/{name}/{filename}.
func (s *Server) pullThroughSource(ctx context.Context, osName, srcPath string) error {
	// src/{os}/{codename}/{upstream}/{component}/{letter}/{name}/{filename}
	segs := strings.Split(srcPath, "/")
	if len(segs) < 8 || segs[0] != "src" {
		return errors.New("invalid src path")
	}
	codename, upstreamName, component, pkgName, filename :=
		segs[2], segs[3], segs[4], segs[6], segs[7]

	// Try the metadata index first (populated by update job).
	entry, err := s.index.FindSourceEntry(ctx,
		model.Selector{OS: osName, Codename: codename, Component: component},
		pkgName, "")
	if err != nil {
		return err
	}
	if entry != nil {
		return s.downloadAndCacheSourceFile(ctx, *entry, upstreamName, filename)
	}

	// Fall back to fetching live Sources from upstream.
	var us *model.UpstreamSource
	for _, layout := range s.cfg.ResolvedLayouts {
		if layout.OS != osName || layout.Codename != codename || layout.Component != component {
			continue
		}
		for i := range layout.Upstreams {
			if layout.Upstreams[i].Name == upstreamName && layout.Upstreams[i].FetchSources {
				us = &layout.Upstreams[i]
				break
			}
		}
		if us != nil {
			break
		}
	}
	if us == nil {
		return fmt.Errorf("upstream %q not found or sources not enabled for %s/%s/%s", upstreamName, osName, codename, component)
	}

	f := upstream.NewFetcher(*us, s.client)
	srcs, err := f.FetchSources(ctx)
	if err != nil {
		return fmt.Errorf("fetch Sources: %w", err)
	}
	for _, raw := range srcs {
		if raw.Package != pkgName {
			continue
		}
		for _, sf := range raw.Files {
			if sf.Filename != filename {
				continue
			}
			data, err := f.DownloadSourceFile(ctx, raw.Directory, filename, sf.SHA256)
			if err != nil {
				return err
			}
			return s.store.PutFile(ctx, srcPath, bytes.NewReader(data), int64(len(data)))
		}
		return fmt.Errorf("file %s not listed in source package %s", filename, pkgName)
	}
	return fmt.Errorf("source package %s not found upstream", pkgName)
}

// downloadAndCacheSourceFile downloads one file using a stored SourceEntry.
func (s *Server) downloadAndCacheSourceFile(ctx context.Context, entry model.SourceEntry, upstreamName, filename string) error {
	var us *model.UpstreamSource
	for _, layout := range s.cfg.ResolvedLayouts {
		if layout.OS != entry.OS || layout.Codename != entry.Codename || layout.Component != entry.Component {
			continue
		}
		for i := range layout.Upstreams {
			if layout.Upstreams[i].Name == upstreamName {
				us = &layout.Upstreams[i]
				break
			}
		}
		if us != nil {
			break
		}
	}
	if us == nil {
		return fmt.Errorf("upstream %q not found in config", upstreamName)
	}
	in := ingest.New(s.store, s.index, s.client, s.notifier, nil)
	return in.CacheSourceFile(ctx, entry, *us, filename)
}

// pullThrough resolves poolPath to an available upstream package and caches it
// together with its dependency closure.
func (s *Server) pullThrough(ctx context.Context, poolPath string) error {
	segs := strings.Split(poolPath, "/")
	if len(segs) < 4 || segs[0] != "pool" {
		return errors.New("invalid pool path")
	}
	osName, codename := segs[1], segs[2]

	entry, err := s.getLive(ctx, osName, codename)
	if err != nil {
		return err
	}
	p, ok := entry.av.ByPoolPath[poolPath]
	if !ok {
		slog.Error("package not in upstream index", "path", poolPath)
		return errors.New("package not available upstream")
	}

	slog.Debug("pull-through", "path", poolPath, "package", p.Name, "version", p.Version, "upstream", p.Upstream.Name)
	in := ingest.New(s.store, s.index, s.client, s.notifier, s.exists)
	return in.Cache(ctx, osName, codename, p)
}

func (s *Server) getLive(ctx context.Context, osName, codename string) (*liveEntry, error) {
	cacheKey := osName + "/" + codename

	s.mu.Lock()
	entry, ok := s.liveCache[cacheKey]
	_, building := s.liveBuilding[cacheKey]

	// Fast path: fresh cache entry.
	if ok && time.Now().Before(entry.expiry) {
		s.mu.Unlock()
		return entry, nil
	}

	// Stale entry exists: return it immediately and refresh in the background.
	if ok {
		if !building {
			wait := make(chan struct{})
			s.liveBuilding[cacheKey] = wait
			go s.rebuildLive(osName, codename, cacheKey, wait)
		}
		s.mu.Unlock()
		return entry, nil
	}

	// No entry at all (cold start). If another goroutine is already building
	// (concurrent first request), wait for it to finish.
	if building {
		wait := s.liveBuilding[cacheKey]
		s.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return s.getLive(ctx, osName, codename)
	}

	// First request with no cached data: build synchronously so the caller
	// gets a real response rather than a stale one.
	wait := make(chan struct{})
	s.liveBuilding[cacheKey] = wait
	s.mu.Unlock()

	// Detach from the client context so a disconnect doesn't abort a build
	// that will populate the cache for subsequent requests.
	buildCtx := context.WithoutCancel(ctx)
	slog.Info("building live cache", "os", osName, "codename", codename)
	buildStart := time.Now()
	av := avail.Build(buildCtx, s.cfg, s.client, s.indexCache, osName, codename)
	files, hashes, err := s.generateLiveFiles(buildCtx, av)
	elapsed := time.Since(buildStart)

	s.mu.Lock()
	delete(s.liveBuilding, cacheKey)
	if err == nil {
		now := time.Now()
		jitter := time.Duration(rand.Int63n(int64(liveTTLJitter)))
		entry = &liveEntry{av: av, files: files, hashes: hashes, built: now, expiry: now.Add(liveTTLBase + jitter)}
		s.sweepExpiredLiveCache(now)
		s.liveCache[cacheKey] = entry
		slog.Info("live cache built", "os", osName, "codename", codename, "elapsed", elapsed)
	} else {
		slog.Error("live file generation failed, no stale data available",
			"os", osName, "codename", codename, "elapsed", elapsed, "err", err)
	}
	s.mu.Unlock()
	close(wait)

	if err != nil {
		return nil, err
	}
	if av.HasStaleMismatch {
		s.startMismatchRetry(osName, codename)
	}
	return entry, nil
}

// rebuildLive runs avail.Build + generateLiveFiles in the background, updating
// the live cache on success. It is launched when a stale entry is served to
// avoid blocking the client on re-generation.
func (s *Server) rebuildLive(osName, codename, cacheKey string, wait chan struct{}) {
	defer close(wait)
	ctx, cancel := context.WithTimeout(context.Background(), retryTimeout)
	defer cancel()

	buildStart := time.Now()
	av := avail.Build(ctx, s.cfg, s.client, s.indexCache, osName, codename)
	files, hashes, err := s.generateLiveFiles(ctx, av)
	elapsed := time.Since(buildStart)

	s.mu.Lock()
	delete(s.liveBuilding, cacheKey)
	swapped := err == nil
	if err == nil {
		now := time.Now()
		jitter := time.Duration(rand.Int63n(int64(liveTTLJitter)))
		newEntry := &liveEntry{av: av, files: files, hashes: hashes, built: now, expiry: now.Add(liveTTLBase + jitter)}
		s.sweepExpiredLiveCache(now)
		s.liveCache[cacheKey] = newEntry
		slog.Debug("live cache refreshed in background", "os", osName, "codename", codename, "elapsed", elapsed)
	} else {
		slog.Error("background live rebuild failed, retaining stale cache",
			"os", osName, "codename", codename, "elapsed", elapsed, "err", err)
	}
	s.mu.Unlock()

	if swapped {
		debug.FreeOSMemory()
	}

	if av.HasStaleMismatch {
		s.startMismatchRetry(osName, codename)
	}
}

var retryDelays = []time.Duration{
	30 * time.Second,
	1 * time.Minute,
	2 * time.Minute,
	4 * time.Minute,
}

const retryTimeout = 10 * time.Minute

// startMismatchRetry launches a background goroutine that retries the live
// build with exponential backoff until a mismatch-free result is obtained or
// the 10-minute deadline is reached. Only one retry runs per os/codename at a
// time; duplicate calls are no-ops.
func (s *Server) startMismatchRetry(osName, codename string) {
	key := osName + "/" + codename
	s.mu.Lock()
	if _, running := s.retryCancel[key]; running {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), retryTimeout)
	s.retryCancel[key] = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.retryCancel, key)
			s.mu.Unlock()
		}()
		for i, delay := range retryDelays {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			// Close idle connections so the retry opens fresh TCP connections,
			// potentially landing on a different CDN node with consistent state.
			s.client.CloseIdleConnections()
			slog.Info("retrying live build after digest mismatch",
				"os", osName, "codename", codename, "attempt", i+1, "delay", delay)
			av := avail.Build(ctx, s.cfg, s.client, s.indexCache, osName, codename)
			if !av.HasStaleMismatch {
				files, hashes, err := s.generateLiveFiles(ctx, av)
				if err != nil {
					slog.Error("mismatch retry: live file generation failed", "os", osName, "codename", codename, "err", err)
					continue
				}
				now := time.Now()
				jitter := time.Duration(rand.Int63n(int64(liveTTLJitter)))
				entry := &liveEntry{av: av, files: files, hashes: hashes, built: now, expiry: now.Add(liveTTLBase + jitter)}
				s.mu.Lock()
				s.liveCache[key] = entry
				s.mu.Unlock()
				slog.Info("mismatch retry succeeded, live cache updated",
					"os", osName, "codename", codename, "attempt", i+1)
				return
			}
			slog.Warn("mismatch retry: upstream still mid-sync",
				"os", osName, "codename", codename, "attempt", i+1)
		}
		slog.Error("mismatch retry exhausted, upstream digest mismatch persists",
			"os", osName, "codename", codename)
	}()
}

func (s *Server) generateLiveFiles(ctx context.Context, av *avail.Available) (map[string][]byte, map[string]string, error) {
	components, arches := s.cfg.ComponentsAndArches(av.OS, av.Codename)

	type comboKey struct{ comp, arch string }
	type comboResult struct {
		key   comboKey
		list  []string
	}
	var combos []comboKey
	for _, comp := range components {
		for _, arch := range arches {
			combos = append(combos, comboKey{comp, arch})
		}
	}

	results := make([]comboResult, len(combos))
	var wg sync.WaitGroup
	for i, ck := range combos {
		wg.Add(1)
		i, ck := i, ck
		go func() {
			defer wg.Done()
			var list []string
			if compMap := av.Pkgs[ck.comp]; compMap != nil {
				if archMap := compMap[ck.arch]; archMap != nil {
					names := make([]string, 0, len(archMap))
					for name := range archMap {
						names = append(names, name)
					}
					sort.Strings(names)
					for _, name := range names {
						list = append(list, stanzaString(archMap[name]))
					}
				}
			}
			results[i] = comboResult{ck, list}
		}()
	}
	wg.Wait()

	stanzas := map[string]map[string][]string{}
	for _, comp := range components {
		stanzas[comp] = map[string][]string{}
	}
	for _, r := range results {
		stanzas[r.key.comp][r.key.arch] = r.list
	}

	// Build source stanzas for components that have upstream Sources data.
	var sourceStanzas map[string][]string
	if av.Srcs != nil {
		sourceStanzas = make(map[string][]string, len(av.Srcs))
		for comp, srcMap := range av.Srcs {
			stanzaList := make([]string, 0, len(srcMap))
			// Sort by package name for deterministic output.
			names := make([]string, 0, len(srcMap))
			for name := range srcMap {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				stanzaList = append(stanzaList, srcMap[name].StanzaStr)
			}
			sourceStanzas[comp] = stanzaList
		}
	}

	sink := newMemSink()
	in := publish.SuiteInput{
		OS:            av.OS,
		Codename:      av.Codename,
		Suite:         av.Codename,
		Origin:        "debproxy",
		Label:         "debproxy-live",
		Description:   "debproxy live view of " + av.OS + "/" + av.Codename,
		Architectures: arches,
		Components:    components,
		Stanzas:       stanzas,
		SourceStanzas: sourceStanzas,
		Date:          time.Now(),
		Compression:   s.cfg.Storage.Compression.ResolveLive(),
		HashTypes:     s.cfg.HashTypesFor(av.OS, av.Codename),
	}
	if err := publish.GenerateSuite(ctx, sink, "", in, s.key); err != nil {
		return nil, nil, err
	}

	// Parse each Release file in the sink once to build a path->sha256 index.
	// This is used by servePlainFromLive for O(1) ETag lookups without re-hashing.
	hashes := make(map[string]string, len(sink.files))
	for key, data := range sink.files {
		if !strings.HasSuffix(key, "/Release") {
			continue
		}
		rel, err := apt.ParseRelease(bytes.NewReader(data))
		if err != nil {
			continue
		}
		// The key is "dists/<codename>/Release"; file paths in Release are relative
		// to "dists/<codename>/", so we reconstruct the full in-memory key.
		prefix := strings.TrimSuffix(key, "Release") // "dists/<codename>/"
		for _, fe := range rel.Files {
			hashes[prefix+fe.Path] = fe.SHA256
		}
	}
	return sink.files, hashes, nil
}


type memSink struct {
	files map[string][]byte
}

func newMemSink() *memSink { return &memSink{files: map[string][]byte{}} }

func (m *memSink) WriteFile(_ context.Context, relPath string, r io.Reader, _ int64) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.files[relPath] = data
	return nil
}

// serveSeekable serves a file with conditional-request and range support via
// http.ServeContent, attaching a weak ETag derived from size and mtime.
func serveSeekable(w http.ResponseWriter, r *http.Request, name string, rc io.ReadCloser, size int64, modtime time.Time) {
	w.Header().Set("Cache-Control", httpCacheControl(r.URL.Path))
	w.Header().Set("Content-Type", contentType(name))
	rs, ok := rc.(io.ReadSeeker)
	if !ok {
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.Copy(w, rc)
		return
	}
	if !modtime.IsZero() {
		w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, size, modtime.UnixNano()))
	}
	http.ServeContent(w, r, path.Base(name), modtime, rs)
}

// servePlainFromLive serves a plain (unencoded) index file by finding a
// compressed variant in entry.files. Plain index files are never stored  --
// their bytes are streamed through compressors during generation.
//
// The ETag is the sha256 of the plain file as recorded in the Release file,
// which was computed once during generation. This is consistent across
// gzip/zstd passthrough and decompressed responses, making If-None-Match work
// regardless of what encoding the client requested.
func (s *Server) servePlainFromLive(w http.ResponseWriter, r *http.Request, key string, entry *liveEntry) {
	accept := r.Header.Get("Accept-Encoding")

	// Decide what to serve.
	var body []byte
	var encoding string
	if strings.Contains(accept, "zstd") {
		if data, ok := entry.files[key+".zst"]; ok {
			encoding, body = "zstd", data
		}
	}
	if body == nil && strings.Contains(accept, "gzip") {
		if data, ok := entry.files[key+".gz"]; ok {
			encoding, body = "gzip", data
		}
	}
	if body == nil {
		for _, sfx := range []string{".zst", ".gz", ".xz"} {
			if data, ok := entry.files[key+sfx]; ok {
				plain, err := decompressBytes(sfx, data)
				if err != nil {
					slog.Warn("decompress live index for plain serve", "key", key, "suffix", sfx, "err", err)
					continue
				}
				body = plain
				break
			}
		}
	}
	if body == nil {
		http.NotFound(w, r)
		return
	}

	// ETag: O(1) lookup in the pre-built hash index (populated once per cache
	// build from the Release data). Encoding-independent so If-None-Match works
	// regardless of whether we serve compressed or plain bytes.
	etag := entry.hashes[key]
	w.Header().Set("Cache-Control", httpCacheControl(r.URL.Path))
	if etag != "" {
		w.Header().Set("ETag", `"`+etag+`"`)
	}
	w.Header().Set("Content-Type", contentType(key))
	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	http.ServeContent(w, r, path.Base(key), entry.built, bytes.NewReader(body))
}

// decompressBytes inflates a compressed buffer into plain bytes.
func decompressBytes(suffix string, data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	switch suffix {
	case ".zst":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case ".gz":
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case ".xz":
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(xr)
	default:
		return nil, fmt.Errorf("unknown suffix %q", suffix)
	}
}

func serveBytes(w http.ResponseWriter, r *http.Request, name string, data []byte, modtime time.Time) {
	sum := sha256.Sum256(data)
	w.Header().Set("Cache-Control", httpCacheControl(r.URL.Path))
	w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sum))
	w.Header().Set("Content-Type", contentType(name))
	http.ServeContent(w, r, path.Base(name), modtime, bytes.NewReader(data))
}

func stanzaString(p avail.Pkg) string {
	return p.StanzaStr
}

// httpCacheControl returns the Cache-Control header value for a request URL
// path. It is keyed on the first path segment (the "selector"):
//   - live/**          -> 12-minute public cache (matches server-side live TTL)
//   - current/**       -> 12-minute public cache (current alias changes on snapshot)
//   - keys/debproxy.*  -> 1-day cache (rotates on key change)
//   - everything else  -> 1-year immutable (pool files and pinned snapshot files)
func httpCacheControl(urlPath string) string {
	parts := strings.SplitN(strings.TrimPrefix(path.Clean("/"+urlPath), "/"), "/", 3)
	if len(parts) == 0 {
		return ""
	}
	switch parts[0] {
	case "live", "current":
		return "public, max-age=720"
	case "keys":
		if len(parts) >= 2 && strings.HasPrefix(parts[1], "debproxy.") {
			return "public, max-age=86400"
		}
		return "public, max-age=31536000, immutable"
	default:
		// pool/, src/, and pinned snapshot paths are all immutable.
		return "public, max-age=31536000, immutable"
	}
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".deb"):
		return "application/vnd.debian.binary-package"
	case strings.HasSuffix(name, ".gz"):
		return "application/gzip"
	case strings.HasSuffix(name, ".xz"):
		return "application/x-xz"
	case strings.HasSuffix(name, ".zst"):
		return "application/zstd"
	case strings.HasSuffix(name, ".bz2"):
		return "application/x-bzip2"
	case strings.HasSuffix(name, "Release.gpg"):
		return "application/pgp-signature"
	case strings.HasSuffix(name, ".gpg"):
		return "application/pgp-keys"
	case strings.HasSuffix(name, ".asc"):
		return "text/plain; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}

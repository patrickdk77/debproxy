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
	"github.com/debproxy/debproxy/internal/safego"
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

	mu               sync.Mutex
	liveCache        map[string]*liveEntry          // key: os/codename
	liveBuilding     map[string]chan struct{}       // in-flight builds
	retryCancel      map[string]context.CancelFunc  // background mismatch retries
	retiredLive      map[string][]*retiredLiveEntry // key: os/codename; see retireLiveEntryLocked
	pendingPeerAdopt map[string]context.CancelFunc  // key: os/codename; see handleLiveUpdatedMessage

	// validOSCodename and validTriple bound metric-label cardinality to the
	// configured universe. Keys are "os/codename" and "os/codename/upstream"
	// respectively, built once from cfg.ResolvedLayouts. Deeper path segments
	// (section, first-letter bucket, package name, filename) are per-package
	// and unbounded, so they're never validated or used as metric labels.
	validOSCodename map[string]bool
	validTriple     map[string]bool

	// valkey optionally backs /live's compressed serving artifacts with a
	// shared Valkey deployment so multiple debproxy replicas avoid redundant
	// compression work. Nil unless EnableValkey is called; see valkey.go.
	valkey *serverValkeyBacking
}

const (
	liveTTLBase   = 12 * time.Minute
	liveTTLJitter = 5 * time.Minute
)

// liveRetiredRetention bounds how long a superseded live generation's files
// remain fetchable after being retired (see retireLiveEntryLocked). This is
// what makes Acquire-By-Hash (see internal/publish) actually safe for the
// dynamically-regenerated /live view: a client that already fetched Release
// (or a by-hash path) from the generation about to be retired must still be
// able to fetch everything that Release referenced, even though /live keeps
// rebuilding out from under it -- otherwise every rebuild would 404 any
// client mid-flight between its Release fetch and its Packages/Sources
// fetch, which is the exact "File has unexpected size" race Acquire-By-Hash
// exists to prevent in the first place.
//
// Must be at least as long as /live's own HTTP Cache-Control max-age (see
// httpCacheControl, which derives its value from liveTTLBase so the two can
// never drift apart): a client -- or an intermediate cache/CDN -- is
// entitled to keep using a Release it fetched for that *entire* window
// before revalidating, and the worst case is a rebuild retiring that exact
// generation moments after the client fetched it, not moments before the
// window closes. An earlier, much shorter 1-minute value let exactly this
// happen in production: a client held a ~3-minute-old Release, its by-hash
// fetch 404'd against the too-short window, and it fell back to the
// plain-named path -- straight back into the race Acquire-By-Hash exists to
// prevent. The 5-minute margin on top of liveTTLBase covers network/
// processing delay and more than one rebuild landing inside the window
// under heavier-than-normal churn.
const liveRetiredRetention = liveTTLBase + 5*time.Minute

var errUnknownSelector = errors.New("unknown snapshot selector")

type liveEntry struct {
	av     *avail.Available
	files  map[string][]byte
	hashes map[string]string // plain file key -> sha256 from Release; O(1) ETag lookup
	built  time.Time
	expiry time.Time
}

// lookupByHash finds the plain-named file whose hash (from Release, see
// hashes' own doc comment) matches hash, and returns its bytes. by-hash
// requests are resolved this way rather than by storing a literal
// by-hash-named entry in files: generateLiveFiles sets
// publish.SuiteInput.SkipByHash, so a by-hash sibling is never written to
// this cache in the first place, which would otherwise be an exact
// duplicate of a plain-named entry's bytes -- doubling /live's in-memory
// footprint, and (via publishLiveUpdate enumerating every key in files)
// doubling every peer replica's adoption fetch traffic and memory too, for
// files that can just as well be served by deriving which plain key a
// given hash belongs to. e.hashes is small (bounded by the number of
// Packages/Sources compressed variants for one layout, typically a few
// dozen at most), so a linear scan here is cheap relative to either an
// HTTP round trip or a re-hash of a multi-MB file.
func (e *liveEntry) lookupByHash(hash string) (data []byte, plainKey string, ok bool) {
	for key, h := range e.hashes {
		if h == hash {
			if d, ok := e.files[key]; ok {
				return d, key, true
			}
		}
	}
	return nil, "", false
}

// retiredLiveEntry is a liveEntry that was superseded by a newer one, kept
// around for liveRetiredRetention so its files stay fetchable by hash. See
// retireLiveEntryLocked/resolveByHash.
type retiredLiveEntry struct {
	entry     *liveEntry
	retiredAt time.Time
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
	validOSCodename := map[string]bool{}
	validTriple := map[string]bool{}
	for _, l := range cfg.ResolvedLayouts {
		validOSCodename[l.OS+"/"+l.Codename] = true
		for _, u := range l.Upstreams {
			validTriple[l.OS+"/"+l.Codename+"/"+u.Name] = true
		}
	}

	return &Server{
		cfg:             cfg,
		store:           store,
		index:           index,
		key:             key,
		client:          client,
		indexCache:      indexCache,
		notifier:        notifier,
		exists:          exists,
		liveCache:        map[string]*liveEntry{},
		liveBuilding:     map[string]chan struct{}{},
		retryCancel:      map[string]context.CancelFunc{},
		retiredLive:      map[string][]*retiredLiveEntry{},
		pendingPeerAdopt: map[string]context.CancelFunc{},
		validOSCodename: validOSCodename,
		validTriple:     validTriple,
	}
}

// isKnownTriple reports whether (os, codename, upstream) matches a configured
// layout. Used at the routing layer to reject requests for combinations that
// could never be served, before any real work (pull-through, live-index
// generation) is attempted for them.
func (s *Server) isKnownTriple(osName, codename, upstream string) bool {
	return s.validTriple[osName+"/"+codename+"/"+upstream]
}

// isKnownOSCodename is the (os, codename)-only analog of isKnownTriple.
func (s *Server) isKnownOSCodename(osName, codename string) bool {
	return s.validOSCodename[osName+"/"+codename]
}

// metricTriple returns (os, codename, upstream) unchanged if they match a
// configured layout, otherwise a single constant sentinel for all three so
// that requests for made-up os/codename/upstream values can't grow the
// PoolHitsTotal/PullThroughsTotal label set without bound.
func (s *Server) metricTriple(osName, codename, upstream string) (string, string, string) {
	if s.validTriple[osName+"/"+codename+"/"+upstream] {
		return osName, codename, upstream
	}
	return "_invalid", "_invalid", "_invalid"
}

// metricOSCodename is the (os, codename)-only analog of metricTriple, for
// metrics that don't carry an upstream label (e.g. SourcePullThroughsTotal).
func (s *Server) metricOSCodename(osName, codename string) (string, string) {
	if s.validOSCodename[osName+"/"+codename] {
		return osName, codename
	}
	return "_invalid", "_invalid"
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

// retireLiveEntryLocked moves old into s.retiredLive[cacheKey] so its files
// (including by-hash-named entries -- see internal/publish's Acquire-By-Hash
// support) remain fetchable for liveRetiredRetention after being superseded,
// pruning any previously-retired entries for this cacheKey that have already
// aged out. Must be called with s.mu held, before old is replaced in
// s.liveCache.
func (s *Server) retireLiveEntryLocked(cacheKey string, old *liveEntry) {
	now := time.Now()
	cutoff := now.Add(-liveRetiredRetention)
	var kept []*retiredLiveEntry
	for _, r := range s.retiredLive[cacheKey] {
		if r.retiredAt.After(cutoff) {
			kept = append(kept, r)
		}
	}
	s.retiredLive[cacheKey] = append(kept, &retiredLiveEntry{entry: old, retiredAt: now})
}

// resolveByHash finds the bytes matching hash for osName/codename, checking
// current first, then recently retired generations (newest first, see
// retireLiveEntryLocked) still within liveRetiredRetention. This is what
// makes Acquire-By-Hash (see internal/publish) actually safe for the
// dynamically-regenerated /live view: a client that already fetched Release
// (or a by-hash path) from a generation about to be retired must still be
// able to fetch everything that Release referenced, even though /live keeps
// rebuilding out from under it -- otherwise every rebuild would 404 any
// client mid-flight between its Release fetch and its Packages/Sources
// fetch, which is the exact "File has unexpected size" race Acquire-By-Hash
// exists to prevent in the first place.
func (s *Server) resolveByHash(osName, codename string, current *liveEntry, hash string) (data []byte, builtAt time.Time, ok bool) {
	if data, _, ok := current.lookupByHash(hash); ok {
		return data, current.built, true
	}

	cacheKey := osName + "/" + codename
	cutoff := time.Now().Add(-liveRetiredRetention)
	s.mu.Lock()
	defer s.mu.Unlock()
	retained := s.retiredLive[cacheKey]
	for i := len(retained) - 1; i >= 0; i-- {
		r := retained[i]
		if r.retiredAt.Before(cutoff) {
			continue
		}
		if data, _, ok := r.entry.lookupByHash(hash); ok {
			return data, r.entry.built, true
		}
	}
	return nil, time.Time{}, false
}

// swapLiveEntry retires whatever was previously cached for osName/codename
// (see retireLiveEntryLocked), installs newEntry as the current one, and --
// only when fresh is true, meaning newEntry was just generated locally
// rather than adopted from a peer that already published its own notice
// (see buildOrAdoptLiveFiles) -- announces it to other replicas.
//
// The swap and the announcement are deliberately sequenced in that order,
// swap first: other replicas (and, once they receive the notice and adopt,
// their own local liveCache) should never be told about a generation this
// replica itself can't yet serve. The announcement itself is fired via
// safego.Go rather than awaited, so a slow or unreachable Valkey never adds
// latency to a request that's just trying to install a build it already
// has in hand.
func (s *Server) swapLiveEntry(osName, codename string, newEntry *liveEntry, fresh bool) {
	cacheKey := osName + "/" + codename

	s.mu.Lock()
	if old, ok := s.liveCache[cacheKey]; ok {
		s.retireLiveEntryLocked(cacheKey, old)
	}
	s.sweepExpiredLiveCache(time.Now())
	s.liveCache[cacheKey] = newEntry
	s.mu.Unlock()

	if fresh && s.valkey != nil {
		safego.Go("publish live update", func() {
			s.publishLiveUpdate(osName, codename, newEntry.files, newEntry.hashes, newEntry.built, newEntry.expiry)
		})
	}
}

// hashFromByHashKey extracts the sha256 hex digest from a by-hash key of the
// form ".../by-hash/SHA256/<hex>", or "" if key doesn't match that shape.
// Used to avoid re-hashing a file that's already named by its own hash just
// to compute its ETag (see serveBytes's callers below) -- without this,
// every by-hash request (which is what apt uses for nearly every
// Packages/Sources fetch once Acquire-By-Hash is advertised, see
// internal/publish) would re-hash a potentially multi-MB file on every
// single request, even though the answer is right there in the URL.
func hashFromByHashKey(key string) string {
	const marker = "/by-hash/SHA256/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
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
		// remainder: [src, os, codename, upstream, ...] -- src storage paths embed
		// os as their own segment (model.SourceDir), same as pool paths do, so it
		// appears a second time here alongside the osName already split off above.
		cn, up := segAt(remainder, 2), segAt(remainder, 3)
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
		if !s.isKnownTriple(osName, cn, up) {
			// Reject before any real work (pull-through, live-index build) is
			// attempted for a combination that could never be served -- not
			// just relabeled to a metrics sentinel after the fact.
			http.NotFound(w, r)
			return
		}
		s.servePool(w, r, strings.Join(remainder, "/"), true, osName, cn, up)
		return
	}
	if remainder[0] == "src" {
		// remainder: [src, os, codename, upstream, ...] -- see the comment on the
		// analogous branch in handleSnapshot for why os appears twice here.
		codename := segAt(remainder, 2)
		if !s.isKnownOSCodename(osName, codename) {
			http.NotFound(w, r)
			return
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
		if !s.isKnownOSCodename(osName, codename) {
			http.NotFound(w, r)
			return
		}
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
		if hash := hashFromByHashKey(key); hash != "" {
			// by-hash paths are resolved virtually, not by a literal key
			// lookup (see liveEntry.lookupByHash for why), checking the
			// current generation and then recently retired ones (see
			// resolveByHash/liveRetiredRetention): a client that fetched
			// Release just before this replica's most recent rebuild may
			// still be fetching Packages/Sources by a hash that generation
			// announced, and that generation's files must stay servable
			// for a little while after being superseded. There's no
			// decompression-fallback equivalent for a by-hash request (it
			// always names one exact stored variant), so a miss here is a
			// straight 404.
			if data, builtAt, ok := s.resolveByHash(osName, codename, entry, hash); ok {
				serveBytes(w, r, key, data, builtAt, hash)
				return
			}
			http.NotFound(w, r)
			return
		}
		data, ok := entry.files[key]
		if !ok {
			// Plain index file (Packages/Sources) is never stored  -- serve from
			// a compressed variant, transparently decoding if the client can't
			// accept any of our compressed formats.
			s.servePlainFromLive(w, r, key, entry)
			return
		}
		serveBytes(w, r, key, data, entry.built, entry.hashes[key])
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
	osLabel, cnLabel, upLabel = s.metricTriple(osLabel, cnLabel, upLabel)
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
		mOS, mCodename := s.metricOSCodename(osName, codename)
		if err := s.pullThroughSource(r.Context(), osName, srcPath); err != nil {
			slog.Error("source pull-through failed", "path", srcPath, "err", err)
			http.Error(w, "source pull-through failed", http.StatusBadGateway)
			metrics.SourcePullThroughsTotal.WithLabelValues(mOS, mCodename, "error").Inc()
			return
		}
		metrics.SourcePullThroughsTotal.WithLabelValues(mOS, mCodename, "success").Inc()
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
		if err := s.downloadAndCacheSourceFile(ctx, *entry, upstreamName, filename); err != nil {
			return err
		}
		entry.FilesDownloaded = true
		if err := s.index.UpsertSourceEntry(ctx, *entry); err != nil {
			slog.Warn("upsert source entry after pull-through", "package", entry.Package, "err", err)
		}
		return nil
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
	if s.exists != nil {
		// pullThrough is only ever called after servePool/serveSrc's own real
		// store.Exists check -- either it just found poolPath missing, or (the
		// re-index branch) found it present but unknown to the exists-cache.
		// Either way, any stale positive entry ExistsCache holds for this
		// exact path (e.g. surviving an out-of-band deletion, see
		// pruneMissingEntries) is proven wrong right now: clear it so Cache
		// re-verifies against real storage instead of trusting it and
		// silently skipping the download.
		s.exists.Remove(poolPath)
	}
	in := ingest.New(s.store, s.index, s.client, s.notifier, s.exists)
	return in.Cache(ctx, osName, codename, p, true)
}

// buildAvail runs avail.Build under s.indexCache's build lock, shared with
// cmd/debproxy's periodic background refresher (both build through the same
// IndexCache) -- so this build never runs concurrently with the refresher's
// own build for some other layout, each of which could otherwise
// independently hold a Valkey fetch lock and resident merge memory at the
// same time.
//
// Only call this from a path that does NOT block a live client request:
// rebuildLive and startMismatchRetry both run in a background goroutine
// after a stale response has already been served, so waiting on this lock
// costs nothing user-facing. getLive's cold-start build is different -- it
// runs synchronously in front of the client, so it calls avail.Build
// directly instead, trading the (rare, small) chance of a memory-overlap
// with a background build for guaranteed low latency on every cold start.
func (s *Server) buildAvail(ctx context.Context, osName, codename string) *avail.Available {
	s.indexCache.Lock()
	defer s.indexCache.Unlock()
	return avail.Build(ctx, s.cfg, s.client, s.indexCache, osName, codename)
}

// buildAvailBestEffort behaves like buildAvail, but never blocks: it takes
// s.indexCache's build lock only if it's immediately free, and builds
// unlocked otherwise. Used by getLive's cold-start path, which runs
// synchronously in front of a live client request -- waiting on an
// unrelated layout's in-progress build would add real, guaranteed latency
// to every cold start, the wrong side of the tradeoff buildAvail's other
// callers accept. Taking the lock whenever it's free still closes the
// common case of the cross-layout memory overlap buildMu exists to
// prevent, without the latency cost of ever waiting for it.
func (s *Server) buildAvailBestEffort(ctx context.Context, osName, codename string) *avail.Available {
	if s.indexCache.TryLock() {
		defer s.indexCache.Unlock()
	}
	return avail.Build(ctx, s.cfg, s.client, s.indexCache, osName, codename)
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
			// This request is about to trigger the same rebuild a pending
			// notice-driven proactive adopt (see handleLiveUpdatedMessage)
			// would otherwise fire after its own jitter delay -- cancel it
			// so it doesn't duplicate the rebuild this request is starting.
			if cancel, pending := s.pendingPeerAdopt[cacheKey]; pending {
				cancel()
				delete(s.pendingPeerAdopt, cacheKey)
			}
			wait := make(chan struct{})
			s.liveBuilding[cacheKey] = wait
			safego.Go("rebuild live cache", func() { s.rebuildLive(osName, codename, cacheKey, wait) })
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
	// that will populate the cache for subsequent requests. Marked
	// WithClientWaiting since this is the one genuine case where a real
	// client HTTP request is synchronously blocked on the result -- see
	// fastFallbackTimeout's doc comment (internal/upstream/fetch.go) for why
	// that marking matters: it's what lets FetchIndex/FetchSources degrade
	// early to stale data here, while background rebuilds and the periodic
	// refresher (neither marked) always spend the full retry budget instead.
	buildCtx := upstream.WithClientWaiting(context.WithoutCancel(ctx))
	slog.Info("building live cache", "os", osName, "codename", codename)
	buildStart := time.Now()
	// Deliberately s.buildAvailBestEffort, not s.buildAvail: this is the
	// cold-start, no-cached-data path, and it runs synchronously in front of
	// a live client request (see the comment above). Blocking on the
	// periodic refresher's unrelated-layout build would trade a rare, small
	// memory-overlap risk for real, guaranteed client-facing latency on
	// every cold start -- the wrong side of that tradeoff -- but taking the
	// lock whenever it's already free costs nothing and closes that overlap
	// window in the common case. rebuildLive and startMismatchRetry below
	// are both background, non-blocking paths and always take the lock.
	av := s.buildAvailBestEffort(buildCtx, osName, codename)
	files, hashes, builtAt, expiry, fresh, err := s.buildOrAdoptLiveFiles(buildCtx, osName, codename, av)
	elapsed := time.Since(buildStart)

	s.mu.Lock()
	delete(s.liveBuilding, cacheKey)
	s.mu.Unlock()
	if err == nil {
		entry = &liveEntry{av: av, files: files, hashes: hashes, built: builtAt, expiry: expiry}
		s.swapLiveEntry(osName, codename, entry, fresh)
		slog.Info("live cache built", "os", osName, "codename", codename, "elapsed", elapsed)
	} else {
		slog.Error("live file generation failed, no stale data available",
			"os", osName, "codename", codename, "elapsed", elapsed, "err", err)
	}
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
	av := s.buildAvail(ctx, osName, codename)
	files, hashes, builtAt, expiry, fresh, err := s.buildOrAdoptLiveFiles(ctx, osName, codename, av)
	elapsed := time.Since(buildStart)

	s.mu.Lock()
	delete(s.liveBuilding, cacheKey)
	s.mu.Unlock()
	swapped := err == nil
	if err == nil {
		newEntry := &liveEntry{av: av, files: files, hashes: hashes, built: builtAt, expiry: expiry}
		s.swapLiveEntry(osName, codename, newEntry, fresh)
		slog.Debug("live cache refreshed in background", "os", osName, "codename", codename, "elapsed", elapsed)
	} else {
		slog.Error("background live rebuild failed, retaining stale cache",
			"os", osName, "codename", codename, "elapsed", elapsed, "err", err)
	}

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
			// Each attempt runs inside safego.Run so a panic during one
			// attempt's build is logged and contained -- the next attempt
			// still runs on schedule -- instead of silently ending the whole
			// retry sequence (or crashing the process). succeeded, set only
			// on the success path below, signals the outer loop to stop
			// after the wrapped closure returns, since a bare `return` inside
			// it would only exit this one attempt, not the loop.
			succeeded := false
			safego.Run(fmt.Sprintf("mismatch retry %s/%s attempt %d", osName, codename, i+1), func() {
				// Close idle connections so the retry opens fresh TCP connections,
				// potentially landing on a different CDN node with consistent state.
				s.client.CloseIdleConnections()
				slog.Info("retrying live build after digest mismatch",
					"os", osName, "codename", codename, "attempt", i+1, "delay", delay)
				av := s.buildAvail(ctx, osName, codename)
				if av.HasStaleMismatch {
					slog.Warn("mismatch retry: upstream still mid-sync",
						"os", osName, "codename", codename, "attempt", i+1)
					return
				}
				files, hashes, builtAt, expiry, fresh, err := s.buildOrAdoptLiveFiles(ctx, osName, codename, av)
				if err != nil {
					slog.Error("mismatch retry: live file generation failed", "os", osName, "codename", codename, "err", err)
					return
				}
				entry := &liveEntry{av: av, files: files, hashes: hashes, built: builtAt, expiry: expiry}
				s.swapLiveEntry(osName, codename, entry, fresh)
				slog.Info("mismatch retry succeeded, live cache updated",
					"os", osName, "codename", codename, "attempt", i+1)
				succeeded = true
			})
			if succeeded {
				return
			}
		}
		slog.Error("mismatch retry exhausted, upstream digest mismatch persists",
			"os", osName, "codename", codename)
	}()
}

func (s *Server) generateLiveFiles(ctx context.Context, av *avail.Available) (map[string][]byte, map[string]string, error) {
	components, arches := s.cfg.ComponentsAndArches(av.OS, av.Codename)

	type comboKey struct{ comp, arch string }
	type comboResult struct {
		key  comboKey
		list []string
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
		// /live is purely in-memory and rebuilt every schedule.refresh cycle
		// -- a literal by-hash sibling here would just be a second,
		// throwaway copy of a plain-named entry's exact bytes, doubling
		// this cache's memory footprint (and, via publishLiveUpdate, every
		// peer's fetch traffic and memory too) for no benefit. by-hash
		// requests are served virtually instead -- see
		// liveEntry.lookupByHash below, which derives the plain path from
		// the hashes index built right below this call.
		SkipByHash: true,
	}
	if err := publish.GenerateSuite(ctx, sink, "", in, s.key); err != nil {
		return nil, nil, err
	}

	// Parse each Release file in the sink once to build a path->sha256 index.
	// This is used by servePlainFromLive for O(1) ETag lookups without
	// re-hashing, and by liveEntry.lookupByHash to resolve by-hash requests.
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

// serveBytes serves data as-is, ETagged with etag if the caller already has
// one (see entry.hashes -- populated once per live cache build rather than
// re-hashing potentially several MB of compressed data on every request).
// Falls back to hashing data itself only when the caller has nothing
// precomputed (e.g. Release/InRelease, which aren't listed in their own
// Release document and so have no entry in entry.hashes).
func serveBytes(w http.ResponseWriter, r *http.Request, name string, data []byte, modtime time.Time, etag string) {
	if etag == "" {
		sum := sha256.Sum256(data)
		etag = fmt.Sprintf("%x", sum)
	}
	w.Header().Set("Cache-Control", httpCacheControl(r.URL.Path))
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("Content-Type", contentType(name))
	http.ServeContent(w, r, path.Base(name), modtime, bytes.NewReader(data))
}

func stanzaString(p avail.Pkg) string {
	return p.StanzaStr
}

// liveHTTPCacheControl is /live's and /current's own Cache-Control value,
// derived from liveTTLBase rather than a second, independent literal -- see
// liveRetiredRetention's own doc comment for why these two must never be
// allowed to drift apart (retention must always cover at least this much
// client-side caching allowance).
var liveHTTPCacheControl = fmt.Sprintf("public, max-age=%d", int(liveTTLBase.Seconds()))

// httpCacheControl returns the Cache-Control header value for a request URL
// path. It is keyed on the first path segment (the "selector"):
//   - live/**          -> public cache for liveTTLBase (matches server-side live TTL)
//   - current/**       -> same as live/** (current alias changes on snapshot)
//   - keys/debproxy.*  -> 1-day cache (rotates on key change)
//   - everything else  -> 1-year immutable (pool files and pinned snapshot files)
func httpCacheControl(urlPath string) string {
	parts := strings.SplitN(strings.TrimPrefix(path.Clean("/"+urlPath), "/"), "/", 3)
	if len(parts) == 0 {
		return ""
	}
	switch parts[0] {
	case "live", "current":
		return liveHTTPCacheControl
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

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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/ingest"
	"github.com/debproxy/debproxy/internal/metadata"
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
	built  time.Time
	expiry time.Time
}

// New creates a Server. notifier may be nil.
func New(cfg *config.Config, store storage.Storage, index metadata.MetadataIndex, key *signing.Key, client *http.Client, indexCache *upstream.IndexCache, notifier *webhook.Notifier) *Server {
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
		liveCache:    map[string]*liveEntry{},
		liveBuilding: map[string]chan struct{}{},
		retryCancel:  map[string]context.CancelFunc{},
	}
}

// Handler returns the HTTP handler with logging and response compression.
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
	return h
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
		s.servePool(w, r, strings.Join(remainder, "/"), false)
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
		s.servePool(w, r, strings.Join(remainder, "/"), true)
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
			http.NotFound(w, r)
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
			http.NotFound(w, r)
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

// servePool serves a pool .deb, pulling it (and its dependency closure) through
// from upstream on first request when allowPullThrough is set.
func (s *Server) servePool(w http.ResponseWriter, r *http.Request, poolPath string, allowPullThrough bool) {
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
			return
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
	in := ingest.New(s.store, s.index, s.client, s.notifier, nil)
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
	av := avail.Build(buildCtx, s.cfg, s.client, s.indexCache, osName, codename)
	files, err := s.generateLiveFiles(buildCtx, av)

	s.mu.Lock()
	delete(s.liveBuilding, cacheKey)
	if err == nil {
		now := time.Now()
		jitter := time.Duration(rand.Int63n(int64(liveTTLJitter)))
		entry = &liveEntry{av: av, files: files, built: now, expiry: now.Add(liveTTLBase + jitter)}
		s.liveCache[cacheKey] = entry
	} else {
		slog.Error("live file generation failed, no stale data available",
			"os", osName, "codename", codename, "err", err)
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

	av := avail.Build(ctx, s.cfg, s.client, s.indexCache, osName, codename)
	files, err := s.generateLiveFiles(ctx, av)

	s.mu.Lock()
	delete(s.liveBuilding, cacheKey)
	if err == nil {
		now := time.Now()
		jitter := time.Duration(rand.Int63n(int64(liveTTLJitter)))
		newEntry := &liveEntry{av: av, files: files, built: now, expiry: now.Add(liveTTLBase + jitter)}
		s.liveCache[cacheKey] = newEntry
		slog.Debug("live cache refreshed in background", "os", osName, "codename", codename)
	} else {
		slog.Error("background live rebuild failed, retaining stale cache",
			"os", osName, "codename", codename, "err", err)
	}
	s.mu.Unlock()

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
				files, err := s.generateLiveFiles(ctx, av)
				if err != nil {
					slog.Error("mismatch retry: live file generation failed", "os", osName, "codename", codename, "err", err)
					continue
				}
				now := time.Now()
				jitter := time.Duration(rand.Int63n(int64(liveTTLJitter)))
				entry := &liveEntry{av: av, files: files, built: now, expiry: now.Add(liveTTLBase + jitter)}
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

func (s *Server) generateLiveFiles(ctx context.Context, av *avail.Available) (map[string][]byte, error) {
	components, arches := s.componentsAndArches(av.OS, av.Codename)

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

	sink := newMemSink()
	in := publish.SuiteInput{
		OS:              av.OS,
		Codename:        av.Codename,
		Suite:           av.Codename,
		Origin:          "debproxy",
		Label:           "debproxy-live",
		Description:     "debproxy live view of " + av.OS + "/" + av.Codename,
		Architectures:   arches,
		Components:      components,
		Stanzas:         stanzas,
		Date:            time.Now(),
		FastCompression: true,
	}
	if err := publish.GenerateSuite(ctx, sink, "", in, s.key); err != nil {
		return nil, err
	}
	return sink.files, nil
}

func (s *Server) componentsAndArches(osName, codename string) ([]string, []string) {
	compSet := map[string]bool{}
	archSet := map[string]bool{}
	for _, l := range s.cfg.ResolvedLayouts {
		if l.OS != osName || l.Codename != codename {
			continue
		}
		compSet[l.Component] = true
		for _, a := range l.Archs {
			archSet[a] = true
		}
	}
	return sortedKeys(compSet), sortedKeys(archSet)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

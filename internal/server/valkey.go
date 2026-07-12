package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// serverValkeyBacking holds the optional shared-cache wiring for a Server's
// /live serving artifacts.
type serverValkeyBacking struct {
	client valkey.Client
	keys   valkeycache.Keys
}

// EnableValkey wires v into s so /live's compressed serving artifacts are
// shared with other debproxy replicas instead of each independently
// compressing its own copy, and starts a background subscriber that
// invalidates the local liveCache entry early when another replica
// publishes a fresher one. Call once at startup; the returned stop func
// must be called on graceful shutdown to stop that subscriber goroutine.
func (s *Server) EnableValkey(ctx context.Context, v valkey.Client, keys valkeycache.Keys) (stop func()) {
	s.valkey = &serverValkeyBacking{client: v, keys: keys}

	subCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		valkeycache.Subscribe(subCtx, v, valkeycache.ChannelLiveUpdated, s.handleLiveUpdatedMessage)
	}()
	return func() {
		cancel()
		<-done
	}
}

// liveUpdatedMsg is the pub/sub payload for events:live-updated.
type liveUpdatedMsg struct {
	OS       string `json:"os"`
	Codename string `json:"codename"`
}

// handleLiveUpdatedMessage invalidates the local liveCache entry for the
// notified os/codename by marking it immediately expired, so the next
// request runs the existing stale-serve-then-background-refresh path
// (getLive/rebuildLive, unchanged) instead of waiting out its own TTL. A
// notification for an os/codename this replica hasn't served yet is a
// no-op: there is no local entry to invalidate, and the next real request
// does a cold-start build, which already checks Valkey first.
func (s *Server) handleLiveUpdatedMessage(msg valkey.PubSubMessage) {
	var m liveUpdatedMsg
	if err := json.Unmarshal([]byte(msg.Message), &m); err != nil {
		slog.Warn("valkey: decode live-updated message failed", "err", err)
		return
	}
	cacheKey := m.OS + "/" + m.Codename
	s.mu.Lock()
	if entry, ok := s.liveCache[cacheKey]; ok {
		expired := *entry
		expired.expiry = time.Time{}
		s.liveCache[cacheKey] = &expired
	}
	s.mu.Unlock()
}

// liveMeta is the JSON-serializable metadata stored at Keys.LiveMeta,
// mirroring liveEntry's non-av fields. Files is tracked separately from
// Hashes because Hashes' key set is a strict superset of Files': a plain,
// uncompressed index path (e.g. "dists/trixie/main/binary-amd64/Packages")
// gets an ETag hash parsed from the Release listing even when only its
// compressed variants (.gz/.zst) are physically stored -- servePlainFromLive
// decompresses one of those on the fly rather than ever storing the plain
// bytes separately. Adopting by Hashes' keys would treat every such entry as
// "missing" and always fall back to a full local rebuild.
type liveMeta struct {
	BuiltAt time.Time
	Expiry  time.Time
	Hashes  map[string]string
	Files   []string
}

// buildOrAdoptLiveFiles returns the compressed serving files for
// osName/codename, adopting them from Valkey if another replica already
// built a fresh copy (avoiding redundant compression work), or generating
// them locally and writing through to Valkey otherwise.
//
// av is always built locally by the caller regardless of what this function
// does (see getLive/rebuildLive/startMismatchRetry): av.ByPoolPath is needed
// for pull-through resolution, and thanks to the upstream Valkey-backed
// IndexCache, avail.Build no longer does real network I/O when another
// replica already refreshed the underlying upstream data -- it becomes
// cheap local merging. generateLiveFiles' compression is the part that's
// actually expensive and worth sharing across replicas.
func (s *Server) buildOrAdoptLiveFiles(ctx context.Context, osName, codename string, av *avail.Available) (files map[string][]byte, hashes map[string]string, builtAt, expiry time.Time, err error) {
	// av.Pkgs/av.Srcs are only ever read below, inside generateLiveFiles (and
	// not at all when adopting from Valkey instead) -- nothing reads them
	// again for the rest of this liveEntry's lifetime once this function
	// returns, only av.ByPoolPath (pull-through) and the top-level fields
	// matter. Clear them here so the per-(component, arch) breakdown --
	// including every Architecture: all package duplicated once per binary
	// arch it's fanned out to, needed to generate output but not to serve
	// afterward -- doesn't sit resident in the live cache for the whole TTL
	// window on top of the compressed bytes already held in files.
	defer func() {
		av.Pkgs = nil
		av.Srcs = nil
	}()

	if s.valkey != nil {
		if files, hashes, builtAt, expiry, ok := s.adoptLiveFromValkey(ctx, osName, codename); ok {
			return files, hashes, builtAt, expiry, nil
		}
	}

	files, hashes, err = s.generateLiveFiles(ctx, av)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	builtAt = time.Now()
	jitter := valkeycache.RandDuration(liveTTLJitter)
	expiry = builtAt.Add(liveTTLBase + jitter)
	if s.valkey != nil {
		s.publishLiveToValkey(ctx, osName, codename, files, hashes, builtAt, expiry)
	}
	return files, hashes, builtAt, expiry, nil
}

// adoptLiveFromValkey reports whether Valkey has an unexpired live-artifact
// entry for osName/codename and, if so, returns its files/hashes/timestamps.
func (s *Server) adoptLiveFromValkey(ctx context.Context, osName, codename string) (files map[string][]byte, hashes map[string]string, builtAt, expiry time.Time, ok bool) {
	b := s.valkey
	meta, ok, err := valkeycache.GetJSON[liveMeta](ctx, b.client, b.keys.LiveMeta(osName, codename))
	if err != nil {
		slog.Warn("valkey: read live meta failed", "os", osName, "codename", codename, "err", err)
		return nil, nil, time.Time{}, time.Time{}, false
	}
	if !ok {
		return nil, nil, time.Time{}, time.Time{}, false
	}
	if !time.Now().Before(meta.Expiry) {
		return nil, nil, time.Time{}, time.Time{}, false
	}
	if len(meta.Files) == 0 {
		return nil, nil, time.Time{}, time.Time{}, false
	}

	relpaths := make([]string, 0, len(meta.Files))
	fileKeys := make([]string, 0, len(meta.Files))
	for _, relpath := range meta.Files {
		relpaths = append(relpaths, relpath)
		fileKeys = append(fileKeys, b.keys.LiveFile(osName, codename, relpath))
	}
	vals, err := b.client.Do(ctx, b.client.B().Mget().Key(fileKeys...).Build()).ToArray()
	if err != nil {
		slog.Warn("valkey: mget live files failed", "os", osName, "codename", codename, "err", err)
		return nil, nil, time.Time{}, time.Time{}, false
	}
	files = make(map[string][]byte, len(relpaths))
	for i, v := range vals {
		str, err := v.ToString()
		if err != nil {
			// A file went missing between reading meta and the MGET (e.g. it
			// expired out independently) -- treat the whole adoption as
			// incomplete rather than serving a partial index.
			slog.Warn("valkey: live file missing, falling back to local build",
				"os", osName, "codename", codename, "file", relpaths[i])
			return nil, nil, time.Time{}, time.Time{}, false
		}
		files[relpaths[i]] = []byte(str)
	}
	return files, meta.Hashes, meta.BuiltAt, meta.Expiry, true
}

// publishLiveToValkey writes files/hashes through to Valkey and notifies
// other replicas via pub/sub. Best-effort: failures are logged, not
// returned, since the local build already succeeded and the caller has
// valid data to serve regardless of whether the shared-cache write succeeds.
func (s *Server) publishLiveToValkey(ctx context.Context, osName, codename string, files map[string][]byte, hashes map[string]string, builtAt, expiry time.Time) {
	b := s.valkey

	// One batched MSET instead of one SET per file -- this runs synchronously
	// in front of a live client's cold-start request (see
	// buildOrAdoptLiveFiles), so N serialized round trips here directly adds
	// N times the latency to that response. All of a layout's LiveFile keys
	// share one hash tag (see valkeycache.Keys.LiveFile), so a single MSET is
	// Cluster-safe the same way adoptLiveFromValkey's MGET already is.
	relpaths := make([]string, 0, len(files))
	if len(files) > 0 {
		mset := b.client.B().Mset().KeyValue()
		for relpath, data := range files {
			relpaths = append(relpaths, relpath)
			mset = mset.KeyValue(b.keys.LiveFile(osName, codename, relpath), string(data))
		}
		if err := b.client.Do(ctx, mset.Build()).Error(); err != nil {
			slog.Warn("valkey: write live files failed", "os", osName, "codename", codename, "err", err)
		}
	}

	meta := liveMeta{BuiltAt: builtAt, Expiry: expiry, Hashes: hashes, Files: relpaths}
	if err := valkeycache.SetJSON(ctx, b.client, b.keys.LiveMeta(osName, codename), meta); err != nil {
		slog.Warn("valkey: write live meta failed", "os", osName, "codename", codename, "err", err)
		return
	}

	msg, _ := json.Marshal(liveUpdatedMsg{OS: osName, Codename: codename})
	if err := valkeycache.Publish(ctx, b.client, valkeycache.ChannelLiveUpdated, string(msg)); err != nil {
		slog.Warn("valkey: publish live update failed", "os", osName, "codename", codename, "err", err)
	}
}

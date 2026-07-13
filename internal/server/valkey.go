package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// serverValkeyBacking holds the optional shared-cache wiring for a Server's
// /live serving artifacts. Only a small pub/sub notice ever goes through
// Valkey (metadata plus the publisher's own reachable addresses) -- the
// compressed file bytes themselves are fetched peer-to-peer over plain HTTP
// directly from whichever replica published them, never written through
// Valkey. This matters because a whole layout's compressed indexes can run
// to hundreds of MB: writing/reading that as a single Valkey value used to
// risk overflowing the pubsub-classified connection's output buffer limit
// (see the design doc's incident writeup), a risk that disappears entirely
// once Valkey never carries file content at all.
type serverValkeyBacking struct {
	client    valkey.Client
	peerAddrs []string     // this replica's own "host:port" candidates, advertised in its own notices
	peerHTTP  *http.Client // short-timeout client used for peer-to-peer fetches

	mu      sync.Mutex
	notices map[string]liveUpdatedMsg // key: os/codename -> most recently received notice
}

// EnableValkey wires v into s so /live build completions are announced to
// other debproxy replicas (letting them fetch the result directly from this
// replica instead of independently recompressing their own copy), and starts
// a background subscriber that does the same when another replica publishes
// first. listenAddr is this process's own --addr (e.g. ":8080"); its port,
// combined with every non-loopback local interface address, forms the
// peerAddrs this replica advertises in its own notices -- other replicas may
// listen on a different port than this one, so each replica must always
// advertise its own, never assume a shared value. Call once at startup; the
// returned stop func must be called on graceful shutdown to stop the
// subscriber goroutine.
func (s *Server) EnableValkey(ctx context.Context, v valkey.Client, listenAddr string) (stop func()) {
	s.valkey = &serverValkeyBacking{
		client:    v,
		peerAddrs: localPeerAddrs(listenAddr),
		peerHTTP:  &http.Client{Timeout: 10 * time.Second},
		notices:   map[string]liveUpdatedMsg{},
	}

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

// localPeerAddrs returns "host:port" candidates other replicas might reach
// this process at: every non-loopback, non-link-local unicast address found
// on any local network interface, combined with listenAddr's own port. No
// assumption is made about the runtime environment (Kubernetes pod IP,
// Docker bridge IP, bare metal, ...) -- every address this process could
// plausibly be dialed at is advertised, and a consuming replica simply tries
// each in turn (see fetchLiveFiles) until one connects or all fail.
func localPeerAddrs(listenAddr string) []string {
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil || portStr == "" || portStr == "0" {
		slog.Warn("valkey: could not determine own listen port for peer-fetch advertising", "listen_addr", listenAddr)
		return nil
	}
	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		slog.Warn("valkey: enumerating local addresses for peer fetch failed", "err", err)
		return nil
	}
	var out []string
	for _, a := range ifaceAddrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, net.JoinHostPort(ip.String(), portStr))
	}
	return out
}

// liveUpdatedMsg is the pub/sub payload for events:live-updated. It carries
// everything a receiving replica needs to adopt the just-published live
// artifacts by fetching them directly from the publisher over HTTP -- see
// the package doc comment on serverValkeyBacking for why only this small
// notice, never file content, ever goes through Valkey.
type liveUpdatedMsg struct {
	OS       string            `json:"os"`
	Codename string            `json:"codename"`
	Addrs    []string          `json:"addrs"`    // publisher's own host:port candidates
	BuiltAt  time.Time         `json:"built_at"`
	Expiry   time.Time         `json:"expiry"`
	Hashes   map[string]string `json:"hashes"`
	Files    []string          `json:"files"` // entry.files map keys, e.g. "dists/noble/main/binary-amd64/Packages.gz"
}

// handleLiveUpdatedMessage records the notice (for the next buildOrAdoptLiveFiles
// call to use, see adoptLiveFromPeer) and invalidates this replica's own
// local liveCache entry for the notified os/codename by marking it
// immediately expired, so the next request runs the existing
// stale-serve-then-background-refresh path (getLive/rebuildLive, unchanged)
// instead of waiting out its own TTL. A notification for an os/codename this
// replica hasn't served yet is a no-op beyond recording the notice: there is
// no local entry to invalidate, and the next real request does a cold-start
// build, which already checks for a recent peer notice first.
func (s *Server) handleLiveUpdatedMessage(msg valkey.PubSubMessage) {
	var m liveUpdatedMsg
	if err := json.Unmarshal([]byte(msg.Message), &m); err != nil {
		slog.Warn("valkey: decode live-updated message failed", "err", err)
		return
	}
	cacheKey := m.OS + "/" + m.Codename

	if s.valkey != nil {
		s.valkey.mu.Lock()
		s.valkey.notices[cacheKey] = m
		s.valkey.mu.Unlock()
	}

	s.mu.Lock()
	if entry, ok := s.liveCache[cacheKey]; ok {
		expired := *entry
		expired.expiry = time.Time{}
		s.liveCache[cacheKey] = &expired
	}
	s.mu.Unlock()
}

// buildOrAdoptLiveFiles returns the compressed serving files for
// osName/codename, adopting them via a direct HTTP fetch from whichever
// replica most recently published a still-fresh build for this layout (see
// adoptLiveFromPeer), or generating them locally and publishing a notice
// otherwise.
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
	// not at all when adopting from a peer instead) -- nothing reads them
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
		if files, hashes, builtAt, expiry, ok := s.adoptLiveFromPeer(ctx, osName, codename); ok {
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
		s.publishLiveUpdate(osName, codename, files, hashes, builtAt, expiry)
	}
	return files, hashes, builtAt, expiry, nil
}

// adoptLiveFromPeer reports whether another replica has recently published a
// still-fresh build for osName/codename and, if so, fetches its files
// directly over HTTP from that replica instead of building locally.
func (s *Server) adoptLiveFromPeer(ctx context.Context, osName, codename string) (files map[string][]byte, hashes map[string]string, builtAt, expiry time.Time, ok bool) {
	b := s.valkey
	cacheKey := osName + "/" + codename

	b.mu.Lock()
	notice, ok := b.notices[cacheKey]
	b.mu.Unlock()
	if !ok {
		return nil, nil, time.Time{}, time.Time{}, false
	}
	if !time.Now().Before(notice.Expiry) {
		return nil, nil, time.Time{}, time.Time{}, false
	}
	if len(notice.Files) == 0 || len(notice.Addrs) == 0 {
		return nil, nil, time.Time{}, time.Time{}, false
	}

	files, err := b.fetchLiveFiles(ctx, osName, notice)
	if err != nil {
		slog.Warn("valkey: fetch live files from peer failed, building locally instead",
			"os", osName, "codename", codename, "err", err)
		return nil, nil, time.Time{}, time.Time{}, false
	}
	return files, notice.Hashes, notice.BuiltAt, notice.Expiry, true
}

// fetchLiveFiles fetches every file in notice.Files from one of notice.Addrs,
// trying each address in turn until one responds successfully to every file
// or all addresses are exhausted.
func (b *serverValkeyBacking) fetchLiveFiles(ctx context.Context, osName string, notice liveUpdatedMsg) (map[string][]byte, error) {
	var lastErr error
	for _, addr := range notice.Addrs {
		files, err := b.fetchLiveFilesFrom(ctx, addr, osName, notice.Files)
		if err == nil {
			return files, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("publisher advertised no reachable addresses")
	}
	return nil, lastErr
}

// fetchLiveFilesFrom fetches every key in keys from addr, over the exact
// same public /live/{os}/{key} route a real apt client would use -- the
// publishing replica needs no separate peer-only API surface, since it
// already serves these exact bytes (a cache hit against its own liveCache,
// per servePlainFromLive/serveBytes) to any caller.
func (b *serverValkeyBacking) fetchLiveFilesFrom(ctx context.Context, addr, osName string, keys []string) (map[string][]byte, error) {
	files := make(map[string][]byte, len(keys))
	for _, key := range keys {
		url := "http://" + addr + "/live/" + osName + "/" + key
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("building request for %s: %w", key, err)
		}
		data, err := b.doFetch(req)
		if err != nil {
			return nil, fmt.Errorf("fetching %s from %s: %w", key, addr, err)
		}
		files[key] = data
	}
	return files, nil
}

func (b *serverValkeyBacking) doFetch(req *http.Request) ([]byte, error) {
	resp, err := b.peerHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// publishLiveUpdate notifies other replicas that osName/codename was just
// built, with enough information (metadata plus this replica's own reachable
// addresses) for them to fetch the files directly instead of independently
// recompressing their own copy. Best-effort: failures are logged, not
// returned, since the local build already succeeded and the caller has valid
// data to serve regardless of whether the notification succeeds.
func (s *Server) publishLiveUpdate(osName, codename string, files map[string][]byte, hashes map[string]string, builtAt, expiry time.Time) {
	b := s.valkey
	if len(b.peerAddrs) == 0 {
		// Nothing else could ever reach this replica for a peer fetch; skip
		// notifying entirely rather than publish a notice no one could use.
		return
	}

	relpaths := make([]string, 0, len(files))
	for relpath := range files {
		relpaths = append(relpaths, relpath)
	}

	msg := liveUpdatedMsg{
		OS: osName, Codename: codename,
		Addrs:   b.peerAddrs,
		BuiltAt: builtAt, Expiry: expiry,
		Hashes: hashes, Files: relpaths,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		slog.Warn("valkey: encode live-updated message failed", "os", osName, "codename", codename, "err", err)
		return
	}
	if err := valkeycache.Publish(context.Background(), b.client, valkeycache.ChannelLiveUpdated, string(data)); err != nil {
		slog.Warn("valkey: publish live update failed", "os", osName, "codename", codename, "err", err)
	}
}

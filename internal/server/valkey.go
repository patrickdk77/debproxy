package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/safego"
	"github.com/debproxy/debproxy/internal/upstream"
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
	client     valkey.Client
	keys       valkeycache.Keys
	peerAddrs  []string     // this replica's own "host:port" candidates, advertised in its own notices
	peerHTTP   *http.Client // bounded-timeout client used for peer-to-peer fetches
	instanceID string       // random per-process ID stamped on this replica's own notices, see handleLiveUpdatedMessage

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
// advertise its own, never assume a shared value. userAgent is the
// configured cfg.UserAgent (may be empty); see peerUserAgentTransport for how
// it's used. keys is used for LiveBuildLock (see rebuildLive), keeping this
// replica's Valkey keys consistent with the rest of the shared cache. Call
// once at startup; the returned stop func must be called on graceful
// shutdown to stop the subscriber goroutine.
func (s *Server) EnableValkey(ctx context.Context, v valkey.Client, keys valkeycache.Keys, listenAddr string, userAgent string) (stop func()) {
	s.valkey = &serverValkeyBacking{
		client:     v,
		keys:       keys,
		peerAddrs:  localPeerAddrs(listenAddr),
		instanceID: newInstanceID(),
		// 30s, not the original 10s: production logs showed this timing out
		// ("Client.Timeout exceeded while awaiting headers") for ordinary
		// Packages.zst-sized fetches whenever the peer replica was itself busy
		// (e.g. mid rebuild for a large layout), forcing an unnecessary local
		// rebuild instead of the cheap peer adopt this path exists for.
		peerHTTP: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &peerUserAgentTransport{
				base:       http.DefaultTransport,
				configured: userAgent,
				fallback:   debproxyUserAgentFallback(),
			},
		},
		notices: map[string]liveUpdatedMsg{},
	}

	subCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	safego.Go("live-updated subscriber", func() {
		defer close(done)
		valkeycache.Subscribe(subCtx, v, valkeycache.ChannelLiveUpdated, func(msg valkey.PubSubMessage) {
			// Wrapped again at the individual-message level, not just around
			// the whole Subscribe call: a panic while handling one malformed
			// or unexpected message (e.g. bad JSON from a peer running a
			// different version) must not tear down the subscription loop
			// itself, only that one message.
			safego.Run("live-updated message handler", func() { s.handleLiveUpdatedMessage(msg) })
		})
	})
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
	Addrs    []string          `json:"addrs"` // publisher's own host:port candidates
	BuiltAt  time.Time         `json:"built_at"`
	Expiry   time.Time         `json:"expiry"` // zero means no timer, see liveEntry.expiry
	Hashes   map[string]string `json:"hashes"`
	Files    []string          `json:"files"`     // entry.files map keys, e.g. "dists/noble/main/binary-amd64/Packages.gz"
	SourceID string            `json:"source_id"` // publisher's serverValkeyBacking.instanceID, see handleLiveUpdatedMessage
	// Unhashed carries, inline, the few files a Release cannot name by
	// hash: dists/<codename>/Release itself, InRelease, and Release.gpg.
	// Every other file in Files is fetched from the publisher by its
	// by-hash URL (see fetchLiveFilesFrom), which is the only way to name
	// the new generation's bytes while the publisher is still serving the
	// previous generation on every plain-named path -- and these three
	// have no by-hash URL to be fetched by.
	//
	// This is the one exception to the rule that file content never goes
	// through Valkey (see serverValkeyBacking's doc comment). It is a
	// bounded one: three files per layout, tens of KB in total, against
	// the hundreds of MB of compressed indexes that made carrying content
	// through pub/sub a problem in the first place. Those still travel
	// peer-to-peer over HTTP and always will.
	Unhashed map[string][]byte `json:"unhashed"`
}

// newInstanceID returns a random per-process identifier, used to recognize
// and ignore this replica's own notices (see handleLiveUpdatedMessage): every
// replica subscribes to the exact channel it also publishes on, so without
// this it would receive its own live-updated notice back and could
// proactively "adopt" its own just-built files from itself over HTTP.
func newInstanceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively impossible in practice; a fixed
		// fallback still can't collide with another replica's real random
		// draw, so self-notice filtering keeps working either way.
		return "unknown-instance"
	}
	return hex.EncodeToString(b)
}

// debproxyUserAgentFallback returns "debproxy <commit>[-dirty]", built the
// same way as the `debproxy version` CLI command (cmd/debproxy/main.go's
// runVersion) -- used as peerUserAgentTransport's last-resort User-Agent when
// neither a live client's own UA nor a configured one is available.
func debproxyUserAgentFallback() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "debproxy"
	}
	commit, dirty := "unknown", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	return fmt.Sprintf("debproxy %s%s", commit, dirty)
}

// peerUserAgentTransport sets the outgoing User-Agent for peer-to-peer
// live-cache fetches. Priority: the real apt client's own User-Agent (via
// upstream.WithUserAgent -- only present when this fetch is running
// synchronously in front of a live client request, i.e. getLive's /live
// cold-start path; every background rebuild -- a stale entry's refresh, the
// notice-driven proactive adopt -- runs on a detached context.Background()
// and carries none) > the configured cfg.UserAgent > a fixed
// "debproxy <commit>" identifier. This is the opposite precedence from
// upstream mirror fetches (internal/upstream/transport.go's
// userAgentTransport, configured > passthrough): a peer fetch never reaches
// a real mirror, so there's no reason to prefer a static configured value
// over the real client's own UA when both are available, and when neither
// is, an identifiable fallback beats leaking Go's bare default.
type peerUserAgentTransport struct {
	base       http.RoundTripper
	configured string
	fallback   string
}

func (t *peerUserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ua, _ := upstream.UserAgentFromContext(req.Context())
	if ua == "" {
		ua = t.configured
	}
	if ua == "" {
		ua = t.fallback
	}
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", ua)
	return t.base.RoundTrip(req)
}

// liveUpdateInvalidateJitter bounds a random delay between receiving a
// live-updated notice and actually invalidating this replica's own local
// liveCache entry for it (see handleLiveUpdatedMessage). A var, not a const,
// so tests can shrink it to keep runtime fast without touching production
// behavior.
//
// Without this, every replica watching the channel invalidates at the exact
// same instant, and invalidation is what makes the *next* incoming client
// request kick off a background fetch from the publisher (see
// getLive/rebuildLive -> adoptLiveFromPeer) -- so for a popular layout under
// continuous request traffic, one notice would otherwise turn into every
// replica hitting the publishing replica's HTTP endpoint for the same files
// within the same fraction of a second. Spreading invalidation itself out
// spreads out when each replica's own first post-notice request notices
// staleness and fetches, without changing anything about the fetch path.
var liveUpdateInvalidateJitter = 10 * time.Second

// byHashPeerFallbackTimeout bounds the entire peer phase of
// resolveByHashWithPeer, across every advertised address it tries. Sized
// for what it actually does -- one already-compressed index file pulled
// from a replica on the same network -- not for the worst case peerHTTP's
// 30s per-request timeout allows, because unlike the adopt path this one
// has an apt client waiting on the other end of it.
//
// A var, not a const, so tests can shrink it; see
// liveUpdateInvalidateJitter.
var byHashPeerFallbackTimeout = 10 * time.Second

// handleLiveUpdatedMessage adopts a peer's freshly-published generation:
// it fetches that generation's files directly from the publisher, stages
// them so they answer by-hash immediately, and promotes them to this
// replica's served generation at a deadline every replica shares.
//
// The deadline is receipt time plus liveSwitchoverDelay. Deriving it from
// local receipt rather than an absolute timestamp in the notice is
// deliberate: pub/sub fanout is milliseconds, so receipt times across
// replicas differ by far less than the clock skew an absolute deadline
// would have to survive. Whichever replica fetches slowest still promotes
// on time as long as it finishes inside the window, and if it overruns it
// promotes as soon as it does finish.
//
// The fetch itself is jittered across replicas (see
// liveUpdateInvalidateJitter) so they don't all hit the publisher at once.
// That stagger applies to the fetch only, never to the promotion -- the
// whole point is that every replica flips at the same moment even though
// they pulled the bytes at different ones.
//
// This deliberately does NOT go through rebuildLive. rebuildLive opens with
// a QuickFingerprint check that returns early, extending the existing
// entry's expiry, whenever upstream Release digests are unchanged. Routing
// adoption through it meant a replica whose own generation was built from
// the same upstream data as the publisher's silently declined to adopt and
// kept serving its own divergent bytes -- and then extended its own expiry,
// so it never reconsidered. Adoption is not a rebuild and must not be
// conditional on upstream having moved.
func (s *Server) handleLiveUpdatedMessage(msg valkey.PubSubMessage) {
	var m liveUpdatedMsg
	if err := json.Unmarshal([]byte(msg.Message), &m); err != nil {
		slog.Warn("valkey: decode live-updated message failed", "err", err)
		return
	}
	if s.valkey != nil && m.SourceID != "" && m.SourceID == s.valkey.instanceID {
		// This replica's own notice, echoed back by the pub/sub subscription
		// it also publishes on -- not a peer. Ignoring it here (rather than
		// filtering only the proactive-adopt trigger) also keeps it out of
		// the notices map entirely, so a later cold-start/stale-entry adopt
		// attempt can never "fetch" from this replica's own advertised
		// address either.
		return
	}
	if s.valkey == nil {
		return
	}
	cacheKey := m.OS + "/" + m.Codename
	promoteAt := time.Now().Add(liveSwitchoverDelay)

	s.valkey.mu.Lock()
	s.valkey.notices[cacheKey] = m
	s.valkey.mu.Unlock()

	if len(m.Files) == 0 || len(m.Addrs) == 0 {
		return
	}

	jitter := valkeycache.RandDuration(liveUpdateInvalidateJitter)
	ctx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	// A newer notice for the same layout supersedes any still-pending
	// adopt from an earlier one -- cancel it so this replica doesn't
	// fetch, stage, and promote a generation the publisher has already
	// moved past.
	if prevCancel, pending := s.pendingPeerAdopt[cacheKey]; pending {
		prevCancel()
	}
	s.pendingPeerAdopt[cacheKey] = cancel
	_, known := s.liveCache[cacheKey]
	s.mu.Unlock()

	if !known {
		// Nothing cached for this layout here, so no client has ever asked
		// this replica for it -- don't spend memory holding a generation
		// for a layout it may never serve. A first request will cold-start
		// it, and buildOrAdoptLiveFiles adopts from this same notice then.
		s.mu.Lock()
		delete(s.pendingPeerAdopt, cacheKey)
		s.mu.Unlock()
		cancel()
		return
	}

	safego.Go("live-updated adopt", func() {
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}

		s.mu.Lock()
		delete(s.pendingPeerAdopt, cacheKey)
		s.mu.Unlock()

		// Each file goes live for by-hash the instant it lands, rather
		// than the whole generation being withheld until the last one
		// does -- see stagePartialLiveEntry. The generation this replica
		// actually advertises is untouched by these; only promotion,
		// after the final complete stage below, changes that.
		onFile := func(sofar map[string][]byte) {
			s.stagePartialLiveEntry(cacheKey, &liveEntry{
				files:  sofar,
				hashes: m.Hashes,
				built:  m.BuiltAt,
				expiry: m.Expiry,
			}, promoteAt)
		}

		files, err := s.valkey.fetchLiveFiles(ctx, m.OS, m, onFile)
		if err != nil {
			// Nothing to install, so this replica keeps serving its
			// current generation. It can still answer by-hash for the
			// peer's generation one file at a time via fetchByHashFromPeer
			// -- see resolveByHashWithPeer.
			slog.Warn("valkey: adopting peer live generation failed, keeping current",
				"os", m.OS, "codename", m.Codename, "err", err)
			return
		}
		if ctx.Err() != nil {
			return
		}

		// av is intentionally carried over from the entry this one
		// replaces rather than rebuilt: it is only read for ByPoolPath
		// (pull-through resolution), the adopted files are what serve
		// /live, and a full avail.Build here would defeat the point of
		// adopting. The next local rebuild refreshes it.
		s.mu.Lock()
		prev, ok := s.liveCache[cacheKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		adopted := &liveEntry{
			av:          prev.av,
			files:       files,
			hashes:      m.Hashes,
			built:       m.BuiltAt,
			expiry:      m.Expiry,
			fingerprint: prev.fingerprint,
		}
		s.stageLiveEntry(m.OS, m.Codename, adopted, promoteAt)
	})
}

// buildOrAdoptLiveFiles returns the compressed serving files for
// osName/codename, adopting them via a direct HTTP fetch from whichever
// replica most recently published a still-fresh build for this layout (see
// adoptLiveFromPeer), or generating them locally otherwise. fresh reports
// which happened: true if this call generated the files itself (the caller
// must then swap them in and announce the new generation -- see
// swapLiveEntry), false if they were adopted from a peer that already did
// so (announcing again here would just echo the same notice back out,
// which every other replica would then also re-announce in turn).
//
// av is always built locally by the caller regardless of what this function
// does (see getLive/rebuildLive/startMismatchRetry): av.ByPoolPath is needed
// for pull-through resolution, and thanks to the upstream Valkey-backed
// IndexCache, avail.Build no longer does real network I/O when another
// replica already refreshed the underlying upstream data -- it becomes
// cheap local merging. generateLiveFiles' compression is the part that's
// actually expensive and worth sharing across replicas.
func (s *Server) buildOrAdoptLiveFiles(ctx context.Context, osName, codename string, av *avail.Available) (files map[string][]byte, hashes map[string]string, builtAt, expiry time.Time, fresh bool, err error) {
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
			return files, hashes, builtAt, expiry, false, nil
		}
	}

	files, hashes, err = s.generateLiveFiles(ctx, av)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, false, err
	}
	builtAt = time.Now()
	expiry = s.liveExpiry(builtAt)
	return files, hashes, builtAt, expiry, true, nil
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
	// A zero Expiry is the publisher telling us its generation has no
	// timer on it at all (schedule.refresh disabled -- see
	// liveEntry.expiry), not that it expired at the epoch.
	if !notice.Expiry.IsZero() && !time.Now().Before(notice.Expiry) {
		return nil, nil, time.Time{}, time.Time{}, false
	}
	if len(notice.Files) == 0 || len(notice.Addrs) == 0 {
		return nil, nil, time.Time{}, time.Time{}, false
	}

	// No incremental staging callback here, unlike the notice-driven adopt
	// in handleLiveUpdatedMessage. This path runs inside
	// buildOrAdoptLiveFiles, whose two callers are a cold start (nothing is
	// being served for this layout yet, so there is no by-hash coverage to
	// widen) and a rebuild (the current generation is still answering
	// by-hash throughout, and the result gets its own full staging window
	// on the way in).
	files, err := b.fetchLiveFiles(ctx, osName, notice, nil)
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
// onFile, when non-nil, is invoked with an independent snapshot of
// everything fetched so far after each individual file lands, so the caller
// can make those files servable before the rest arrive. It is called from
// the fetching goroutine and must not block for long.
func (b *serverValkeyBacking) fetchLiveFiles(ctx context.Context, osName string, notice liveUpdatedMsg, onFile func(map[string][]byte)) (map[string][]byte, error) {
	var lastErr error
	for _, addr := range notice.Addrs {
		files, err := b.fetchLiveFilesFrom(ctx, addr, osName, notice, onFile)
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

// fetchOrder returns notice.Files with every hash-addressable file first
// (sorted, so two replicas fetch in the same order and the publisher sees a
// predictable access pattern), then the few that aren't.
//
// The ordering is what makes by-hash coverage grow as fast as it possibly
// can: the hashed files are the only ones a client can request by hash, and
// they are also the big ones. Release/InRelease/Release.gpg cannot be
// requested by hash at all, are already in hand from the notice itself, and
// matter only at promotion -- so they sort last, leaving InRelease
// effectively the final thing this replica takes on before the generation
// goes live.
func fetchOrder(notice liveUpdatedMsg) []string {
	var hashed, plain []string
	for _, key := range notice.Files {
		if notice.Hashes[key] != "" {
			hashed = append(hashed, key)
		} else {
			plain = append(plain, key)
		}
	}
	sort.Strings(hashed)
	sort.Strings(plain)
	return append(hashed, plain...)
}

// fetchLiveFilesFrom fetches every file the notice names from addr, over
// the exact same public /live/{os}/... route a real apt client would use --
// the publishing replica needs no separate peer-only API surface, since it
// already serves these exact bytes to any caller.
//
// Each file is fetched by its BY-HASH url, never by its plain name, and
// that is load-bearing rather than a stylistic choice. The publisher
// staged this generation instead of installing it (see
// Server.stageLiveEntry), so for the whole switchover window its
// plain-named paths still serve the PREVIOUS generation. A plain-named
// peer fetch during that window would quietly copy the old bytes under the
// new generation's keys and stage a chimera: a Release naming hashes that
// none of the files beside it actually have. The by-hash url names the
// exact bytes wanted regardless of what is currently current anywhere.
//
// The handful of files with no hash to be named by -- Release, InRelease,
// Release.gpg -- ride along inside the notice instead; see
// liveUpdatedMsg.Unhashed.
func (b *serverValkeyBacking) fetchLiveFilesFrom(ctx context.Context, addr, osName string, notice liveUpdatedMsg, onFile func(map[string][]byte)) (map[string][]byte, error) {
	files := make(map[string][]byte, len(notice.Files))
	for _, key := range fetchOrder(notice) {
		if data, ok := notice.Unhashed[key]; ok {
			files[key] = data
			continue
		}
		hash := notice.Hashes[key]
		if hash == "" {
			return nil, fmt.Errorf("notice names %s with neither a hash nor inline content", key)
		}
		url := "http://" + addr + "/live/" + osName + "/" + byHashKey(key, hash)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("building request for %s: %w", key, err)
		}
		data, err := b.doFetch(req)
		if err != nil {
			return nil, fmt.Errorf("fetching %s from %s: %w", key, addr, err)
		}
		files[key] = data
		if onFile != nil {
			// An independent copy: the callback publishes this map where
			// other goroutines will read it, and the loop keeps writing to
			// files. Only the map is copied, never the file contents.
			snapshot := make(map[string][]byte, len(files))
			for k, v := range files {
				snapshot[k] = v
			}
			onFile(snapshot)
		}
	}
	return files, nil
}

// resolveByHashWithPeer resolves hash locally (see resolveByHash) and, on a
// miss, fetches that one file from whichever peer most recently announced a
// generation containing it.
//
// This is the last line of defence behind staging, not the mechanism that
// makes cross-replica by-hash work -- staging is. It covers the cases
// staging cannot: a notice this replica never received because Valkey was
// briefly unreachable, an adopt whose fetch failed, or a replica that
// joined the cluster after the current generation was announced. In all of
// those this replica is missing a generation its peers have, and the
// alternative to one extra intra-cluster GET is a 404 that sends apt back
// to the plain-named path and produces a "File has unexpected size" for a
// real user.
//
// Only ever fetches a file the peer's own notice named at exactly this
// hash, and the response is content-addressed by construction, so a
// misbehaving peer cannot substitute different bytes without the hash in
// the url ceasing to describe them.
//
// Unlike the adopt path, this runs inside a real client request, so the
// whole peer phase is bounded by byHashPeerFallbackTimeout across every
// address tried rather than by peerHTTP's much longer per-request timeout.
// A slow peer must not turn one apt request into a minutes-long stall: a
// prompt 404 costs the client a plain-path retry, which is bad, while a
// stalled connection can hold up its entire update run.
func (s *Server) resolveByHashWithPeer(ctx context.Context, osName, codename string, current *liveEntry, hash string) (data []byte, builtAt time.Time, ok bool) {
	if data, builtAt, ok := s.resolveByHash(osName, codename, current, hash); ok {
		return data, builtAt, true
	}
	if s.valkey == nil {
		return nil, time.Time{}, false
	}

	ctx, cancel := context.WithTimeout(ctx, byHashPeerFallbackTimeout)
	defer cancel()

	cacheKey := osName + "/" + codename
	s.valkey.mu.Lock()
	notice, haveNotice := s.valkey.notices[cacheKey]
	s.valkey.mu.Unlock()
	if !haveNotice || len(notice.Addrs) == 0 {
		return nil, time.Time{}, false
	}

	key, named := "", false
	for k, h := range notice.Hashes {
		if h == hash {
			key, named = k, true
			break
		}
	}
	if !named {
		return nil, time.Time{}, false
	}

	var lastErr error
	for _, addr := range notice.Addrs {
		url := "http://" + addr + "/live/" + osName + "/" + byHashKey(key, hash)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := s.valkey.doFetch(req)
		if err != nil {
			lastErr = err
			continue
		}
		slog.Debug("live by-hash served from peer after local miss",
			"os", osName, "codename", codename, "key", key)
		return data, notice.BuiltAt, true
	}
	slog.Warn("live by-hash peer fallback failed",
		"os", osName, "codename", codename, "key", key, "err", lastErr)
	return nil, time.Time{}, false
}

// byHashKey rewrites a plain-named live key into the by-hash key naming the
// identical bytes, matching the layout publish.byHashPath writes and
// hashFromByHashKey parses: "dists/n/main/binary-amd64/Packages.zst" plus
// hash h becomes "dists/n/main/binary-amd64/by-hash/SHA256/<h>".
func byHashKey(key, hash string) string {
	return path.Join(path.Dir(key), "by-hash", "SHA256", hash)
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
func (s *Server) publishLiveUpdate(osName, codename string, entry *liveEntry) {
	b := s.valkey
	if len(b.peerAddrs) == 0 {
		// Nothing else could ever reach this replica for a peer fetch; skip
		// notifying entirely rather than publish a notice no one could use.
		return
	}

	// Files a Release names by hash are fetched from this replica by
	// by-hash url; the rest (Release, InRelease, Release.gpg) have no such
	// url and travel inline. See liveUpdatedMsg.Unhashed.
	relpaths := make([]string, 0, len(entry.files))
	unhashed := map[string][]byte{}
	for relpath, data := range entry.files {
		relpaths = append(relpaths, relpath)
		if entry.hashes[relpath] == "" {
			unhashed[relpath] = data
		}
	}

	msg := liveUpdatedMsg{
		OS: osName, Codename: codename,
		Addrs:   b.peerAddrs,
		BuiltAt: entry.built, Expiry: entry.expiry,
		Hashes: entry.hashes, Files: relpaths,
		SourceID: b.instanceID,
		Unhashed: unhashed,
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

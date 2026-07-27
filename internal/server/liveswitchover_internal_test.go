package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
)

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestByHashKeyRoundTripsWithHashFromByHashKey pins the two halves of the
// by-hash path convention together. byHashKey builds the url a peer fetch
// asks for; hashFromByHashKey parses the one an inbound request arrives on.
// If they ever disagree about the shape, peer fetches silently stop
// resolving and every adopt falls back to a local rebuild -- the exact
// divergence staging exists to prevent, with no error anywhere to show for
// it.
func TestByHashKeyRoundTripsWithHashFromByHashKey(t *testing.T) {
	const hash = "aabbccdd"
	cases := []struct{ key, want string }{
		{
			"dists/trixie/main/binary-amd64/Packages.gz",
			"dists/trixie/main/binary-amd64/by-hash/SHA256/aabbccdd",
		},
		{
			"dists/trixie/main/source/Sources.xz",
			"dists/trixie/main/source/by-hash/SHA256/aabbccdd",
		},
		{
			"dists/noble/universe/binary-arm64/Packages.zst",
			"dists/noble/universe/binary-arm64/by-hash/SHA256/aabbccdd",
		},
	}
	for _, c := range cases {
		got := byHashKey(c.key, hash)
		if got != c.want {
			t.Errorf("byHashKey(%q) = %q, want %q", c.key, got, c.want)
		}
		if parsed := hashFromByHashKey(got); parsed != hash {
			t.Errorf("hashFromByHashKey(%q) = %q, want %q", got, parsed, hash)
		}
	}
}

// TestPeerFetchUsesByHashNotPlainPath is the regression test for the
// subtlest failure mode in the switchover design. While a publisher holds a
// new generation staged, every one of its plain-named paths still serves
// the PREVIOUS generation -- that is the entire point of staging. A peer
// that fetched by plain name during that window would copy the old bytes in
// under the new generation's keys and stage a chimera: a Release naming
// hashes that none of the files beside it actually have. Every by-hash
// request against that replica would then miss, and every client would fall
// back to the plain path and hit "File has unexpected size".
//
// Nothing about that failure is visible in the fetch itself; it succeeds,
// with 200s throughout. So this test makes the two generations differ and
// proves the fetch followed the by-hash url.
func TestPeerFetchUsesByHashNotPlainPath(t *testing.T) {
	const key = "dists/trixie/main/binary-amd64/Packages.gz"
	oldBytes := []byte("previous generation, still on every plain path")
	newBytes := []byte("staged generation, reachable only by hash")

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files:  map[string][]byte{key: oldBytes},
		hashes: map[string]string{key: hashOf(oldBytes)},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	publisher.stagedLive["debian/trixie"] = &stagedLiveEntry{
		entry: &liveEntry{
			files:  map[string][]byte{key: newBytes},
			hashes: map[string]string{key: hashOf(newBytes)},
			built:  time.Now(),
			expiry: time.Now().Add(time.Hour),
		},
		promoteAt: time.Now().Add(time.Hour),
	}
	srv := httptest.NewServer(publisher.Handler())
	defer srv.Close()

	b := &serverValkeyBacking{peerHTTP: &http.Client{Timeout: 2 * time.Second}}
	notice := liveUpdatedMsg{
		Addrs:  []string{srv.Listener.Addr().String()},
		Files:  []string{key},
		Hashes: map[string]string{key: hashOf(newBytes)},
	}

	files, err := b.fetchLiveFiles(context.Background(), "debian", notice, nil)
	if err != nil {
		t.Fatalf("fetchLiveFiles: %v", err)
	}
	if string(files[key]) == string(oldBytes) {
		t.Fatal("peer fetch followed the plain-named path and copied the publisher's PREVIOUS generation; it must fetch by hash so it gets the generation the notice actually announced")
	}
	if string(files[key]) != string(newBytes) {
		t.Fatalf("files[%q] = %q, want the staged generation %q", key, files[key], newBytes)
	}
}

// TestFetchOrderPutsHashAddressableFilesFirst pins the fetch ordering that
// makes by-hash coverage grow as fast as it can. Only hashed files can be
// requested by hash at all, so they must all land before the ones that
// cannot -- leaving InRelease, which a client reads to learn those hashes
// in the first place, effectively last.
func TestFetchOrderPutsHashAddressableFilesFirst(t *testing.T) {
	notice := liveUpdatedMsg{
		Files: []string{
			"dists/trixie/InRelease",
			"dists/trixie/main/binary-amd64/Packages.gz",
			"dists/trixie/Release.gpg",
			"dists/trixie/main/source/Sources.gz",
			"dists/trixie/Release",
		},
		Hashes: map[string]string{
			"dists/trixie/main/binary-amd64/Packages.gz": "h1",
			"dists/trixie/main/source/Sources.gz":        "h2",
		},
	}

	got := fetchOrder(notice)
	if len(got) != len(notice.Files) {
		t.Fatalf("fetchOrder dropped or duplicated files: got %v", got)
	}
	for i, key := range got {
		hashed := notice.Hashes[key] != ""
		if i < 2 && !hashed {
			t.Errorf("position %d is %q, want a hash-addressable file", i, key)
		}
		if i >= 2 && hashed {
			t.Errorf("position %d is hash-addressable %q, want it fetched before the unhashed files", i, key)
		}
	}
	// Ordering must also be stable, so replicas fetch alike and a retry
	// against a second address repeats the same sequence.
	if second := fetchOrder(notice); !equalStrings(got, second) {
		t.Errorf("fetchOrder is not stable: %v then %v", got, second)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFetchLiveFilesStagesEachFileAsItArrives is the test for "by-hash goes
// live as soon as it is available". A peer pulling a large layout can take
// most of the switchover window; if its files only became resolvable once
// the last one landed, a client whose Release came from the publisher would
// 404 here for that entire time and fall back to the plain-named path.
//
// So the callback must fire per file, each time carrying everything fetched
// so far, and each snapshot must be independent -- the fetch loop keeps
// writing to its own map, and a snapshot handed to the callback is
// published where other goroutines read it.
func TestFetchLiveFilesStagesEachFileAsItArrives(t *testing.T) {
	keyA := "dists/trixie/main/binary-amd64/Packages.gz"
	keyB := "dists/trixie/main/source/Sources.gz"
	relKey := "dists/trixie/InRelease"
	dataA, dataB := []byte("packages"), []byte("sources")

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files:  map[string][]byte{keyA: dataA, keyB: dataB},
		hashes: map[string]string{keyA: hashOf(dataA), keyB: hashOf(dataB)},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	srv := httptest.NewServer(publisher.Handler())
	defer srv.Close()

	b := &serverValkeyBacking{peerHTTP: &http.Client{Timeout: 2 * time.Second}}
	notice := liveUpdatedMsg{
		Addrs:    []string{srv.Listener.Addr().String()},
		Files:    []string{keyA, keyB, relKey},
		Hashes:   map[string]string{keyA: hashOf(dataA), keyB: hashOf(dataB)},
		Unhashed: map[string][]byte{relKey: []byte("inrelease")},
	}

	var snapshots []map[string][]byte
	files, err := b.fetchLiveFiles(context.Background(), "debian", notice, func(sofar map[string][]byte) {
		snapshots = append(snapshots, sofar)
	})
	if err != nil {
		t.Fatalf("fetchLiveFiles: %v", err)
	}

	// One per hashed file. The unhashed ones come from the notice itself
	// and cannot be requested by hash, so they need no interim snapshot.
	if len(snapshots) != 2 {
		t.Fatalf("got %d incremental snapshots, want one per hash-addressable file", len(snapshots))
	}
	if len(snapshots[1]) != 2 {
		t.Errorf("second snapshot has %d files, want both fetched so far", len(snapshots[1]))
	}
	// Checked after the whole fetch finished, so this also proves the
	// snapshots are independent: were they the same map, or a view onto the
	// loop's own, this one would have grown to 3 by now.
	if len(snapshots[0]) != 1 {
		t.Errorf("first snapshot has %d files, want exactly the one file fetched at the time it was handed over -- a snapshot is published where other goroutines read it and must not keep growing", len(snapshots[0]))
	}
	if len(files) != 3 {
		t.Errorf("final result has %d files, want all 3", len(files))
	}
}

// TestFetchLiveFilesRejectsKeyWithNoHashAndNoInlineContent covers a
// malformed or version-skewed notice. A key that is neither hashed (so it
// has a by-hash url) nor carried inline is unfetchable, and the only safe
// outcome is a hard error: silently dropping it would stage a generation
// missing a file its own Release names.
func TestFetchLiveFilesRejectsKeyWithNoHashAndNoInlineContent(t *testing.T) {
	const key = "dists/trixie/main/binary-amd64/Packages.gz"

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	srv := httptest.NewServer(publisher.Handler())
	defer srv.Close()

	b := &serverValkeyBacking{peerHTTP: &http.Client{Timeout: 2 * time.Second}}
	notice := liveUpdatedMsg{
		Addrs:  []string{srv.Listener.Addr().String()},
		Files:  []string{key},
		Hashes: map[string]string{}, // no hash
		// and no Unhashed entry either
	}

	files, err := b.fetchLiveFiles(context.Background(), "debian", notice, nil)
	if err == nil {
		t.Fatalf("expected an error for an unfetchable key, got files=%v", files)
	}
	if files != nil {
		t.Errorf("expected no partial file map alongside the error, got %v", files)
	}
}

// TestStageLiveEntryPromotesImmediatelyOnColdStart covers the one case that
// must not wait: with nothing cached for the layout, staging would leave a
// client with no generation to read at all. There is also nothing to
// protect -- no client can be holding an older InRelease from this replica
// -- so the deadline buys nothing.
func TestStageLiveEntryPromotesImmediatelyOnColdStart(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	entry := &liveEntry{built: time.Now(), expiry: time.Now().Add(time.Hour)}

	s.stageLiveEntry("debian", "trixie", entry, time.Now().Add(time.Hour))

	s.mu.Lock()
	current := s.liveCache["debian/trixie"]
	_, staged := s.stagedLive["debian/trixie"]
	s.mu.Unlock()

	if current != entry {
		t.Error("cold start did not promote immediately; the layout would be unservable for the whole switchover window")
	}
	if staged {
		t.Error("cold start left an entry in the staging slot")
	}
}

// TestPromoteStagedEntrySkipsSupersededGeneration covers the race between a
// staged generation's own promotion timer and a newer generation arriving
// before it fires. The older timer must not install its entry over the
// newer one, which would walk this replica backwards to a generation the
// publisher has already moved past.
func TestPromoteStagedEntrySkipsSupersededGeneration(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	cacheKey := "debian/trixie"

	current := &liveEntry{built: time.Now()}
	older := &liveEntry{built: time.Now()}
	newer := &liveEntry{built: time.Now()}
	s.liveCache[cacheKey] = current
	s.stagedLive[cacheKey] = &stagedLiveEntry{entry: newer, promoteAt: time.Now().Add(time.Hour)}

	// The superseded generation's timer fires late.
	s.promoteStagedEntry(cacheKey, older)

	s.mu.Lock()
	got := s.liveCache[cacheKey]
	stillStaged := s.stagedLive[cacheKey]
	s.mu.Unlock()

	if got == older {
		t.Fatal("a superseded generation's promotion timer installed it anyway, rolling this replica back to a generation its peers have already moved past")
	}
	if got != current {
		t.Errorf("current generation changed unexpectedly")
	}
	if stillStaged == nil || stillStaged.entry != newer {
		t.Error("the newer staged generation was disturbed by the superseded timer")
	}
}

// TestResolveByHashFallsBackToPeerOnLocalMiss covers the safety net behind
// staging: a notice this replica never received (a Valkey blip, an adopt
// whose fetch failed, a replica that joined late) leaves it unable to answer
// for a generation its peers are serving. One extra intra-cluster GET beats
// a 404, which would send apt back to the plain-named path and produce a
// user-visible "File has unexpected size".
func TestResolveByHashFallsBackToPeerOnLocalMiss(t *testing.T) {
	const key = "dists/trixie/main/binary-amd64/Packages.gz"
	peerBytes := []byte("only the peer has this generation")
	peerHash := hashOf(peerBytes)

	publisher := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	publisher.liveCache["debian/trixie"] = &liveEntry{
		files:  map[string][]byte{key: peerBytes},
		hashes: map[string]string{key: peerHash},
		built:  time.Now(),
		expiry: time.Now().Add(time.Hour),
	}
	srv := httptest.NewServer(publisher.Handler())
	defer srv.Close()

	s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
	s.valkey = &serverValkeyBacking{
		instanceID: "local",
		peerHTTP:   &http.Client{Timeout: 2 * time.Second},
		notices: map[string]liveUpdatedMsg{
			"debian/trixie": {
				OS: "debian", Codename: "trixie",
				Addrs:  []string{srv.Listener.Addr().String()},
				Files:  []string{key},
				Hashes: map[string]string{key: peerHash},
			},
		},
	}
	// This replica has a generation, just not the one being asked for.
	local := &liveEntry{
		files:  map[string][]byte{key: []byte("a different generation")},
		hashes: map[string]string{key: "somethingelse"},
		built:  time.Now(),
	}
	s.liveCache["debian/trixie"] = local

	data, _, ok := s.resolveByHashWithPeer(context.Background(), "debian", "trixie", local, peerHash)
	if !ok {
		t.Fatal("expected the peer fallback to satisfy a hash this replica never had")
	}
	if string(data) != string(peerBytes) {
		t.Fatalf("got %q, want %q", data, peerBytes)
	}
}

// TestResolveByHashPeerFallbackFailsClosed covers the fallback's error
// paths. An unreachable peer, and a hash no notice ever named, must both
// resolve to a clean miss rather than a hang, a panic, or bytes from
// somewhere else.
func TestResolveByHashPeerFallbackFailsClosed(t *testing.T) {
	const key = "dists/trixie/main/binary-amd64/Packages.gz"
	local := &liveEntry{hashes: map[string]string{}, files: map[string][]byte{}, built: time.Now()}

	t.Run("peer unreachable", func(t *testing.T) {
		s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
		s.valkey = &serverValkeyBacking{
			peerHTTP: &http.Client{Timeout: 500 * time.Millisecond},
			notices: map[string]liveUpdatedMsg{
				"debian/trixie": {
					Addrs:  []string{"127.0.0.1:1"}, // nothing listens here
					Files:  []string{key},
					Hashes: map[string]string{key: "wantedhash"},
				},
			},
		}
		s.liveCache["debian/trixie"] = local

		if _, _, ok := s.resolveByHashWithPeer(context.Background(), "debian", "trixie", local, "wantedhash"); ok {
			t.Error("expected a miss when no peer address is reachable")
		}
	})

	t.Run("hash named by no notice", func(t *testing.T) {
		s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
		s.valkey = &serverValkeyBacking{
			peerHTTP: &http.Client{Timeout: 500 * time.Millisecond},
			notices: map[string]liveUpdatedMsg{
				"debian/trixie": {
					Addrs:  []string{"127.0.0.1:1"},
					Files:  []string{key},
					Hashes: map[string]string{key: "someotherhash"},
				},
			},
		}
		s.liveCache["debian/trixie"] = local

		// Must not even attempt a fetch: the peer never claimed this hash.
		if _, _, ok := s.resolveByHashWithPeer(context.Background(), "debian", "trixie", local, "unknownhash"); ok {
			t.Error("expected a miss for a hash no notice ever named")
		}
	})

	t.Run("valkey disabled", func(t *testing.T) {
		s := New(testLayoutConfig(), nil, nil, nil, nil, nil, nil, nil)
		s.liveCache["debian/trixie"] = local

		if _, _, ok := s.resolveByHashWithPeer(context.Background(), "debian", "trixie", local, "wantedhash"); ok {
			t.Error("expected a miss with no valkey backing configured")
		}
	})
}

// TestLiveExpiryFollowsRefreshAndDisablesCleanly covers both halves of the
// expiry model that replaced the old fixed 12-minute TTL: it tracks
// schedule.refresh when set, and a disabled refresh yields the zero value,
// which stale() must read as "never stale" rather than "expired at the
// epoch".
func TestLiveExpiryFollowsRefreshAndDisablesCleanly(t *testing.T) {
	now := time.Now()

	t.Run("tracks schedule.refresh", func(t *testing.T) {
		s := New(&config.Config{Schedule: config.ScheduleConfig{Refresh: "3h"}},
			nil, nil, nil, nil, nil, nil, nil)
		got := s.liveExpiry(now)
		if got.Before(now.Add(3 * time.Hour)) {
			t.Errorf("expiry %v is earlier than refresh alone (%v)", got, now.Add(3*time.Hour))
		}
		if got.After(now.Add(3*time.Hour + liveExpiryJitter)) {
			t.Errorf("expiry %v exceeds refresh plus the jitter bound", got)
		}
		if (&liveEntry{expiry: got}).stale(now) {
			t.Error("a freshly dated entry read as stale")
		}
	})

	t.Run("refresh disabled means no timer", func(t *testing.T) {
		for _, raw := range []string{"", "0"} {
			s := New(&config.Config{Schedule: config.ScheduleConfig{Refresh: raw}},
				nil, nil, nil, nil, nil, nil, nil)
			got := s.liveExpiry(now)
			if !got.IsZero() {
				t.Errorf("refresh=%q: expiry = %v, want the zero value", raw, got)
			}
			// The trap this guards: time.Now().After(time.Time{}) is true,
			// so a bare comparison would call every such entry stale and
			// rebuild the layout on literally every request.
			if (&liveEntry{expiry: got}).stale(now.Add(1000 * time.Hour)) {
				t.Errorf("refresh=%q: a no-timer entry read as stale", raw)
			}
		}
	})
}

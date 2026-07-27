package server

import (
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
)

// TestSweepExpiredLiveCacheKeepsExpiredEntryForStillConfiguredLayout is the
// direct regression test for a real production incident: sweepExpiredLiveCache
// used to delete any entry past its own expiry, for every layout, on every
// single generation swap (i.e. on every successful build for ANY layout,
// not just the one being swept). That silently defeated getLive's own
// stale-entry fast path (serve the stale entry immediately, refresh in the
// background) for any *other*, currently-configured layout that simply
// hadn't been requested recently enough to still be inside its own TTL
// window -- the next request for it then fell all the way through to the
// synchronous cold-start path and blocked that client on a full rebuild,
// observed in production as repeated "building live cache"/"live cache
// built" pairs for the same os/codename long after startup, well after the
// process had been running fine.
//
// A still-configured layout's entry must survive the sweep no matter how
// old it is -- getLive is the one responsible for refreshing it, not this
// sweep.
func TestSweepExpiredLiveCacheKeepsExpiredEntryForStillConfiguredLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	expired := &liveEntry{
		built:  time.Now().Add(-24 * time.Hour),
		expiry: time.Now().Add(-time.Hour),
	}
	s.liveCache["debian/trixie"] = expired

	s.mu.Lock()
	s.sweepExpiredLiveCache(time.Now())
	s.mu.Unlock()

	if s.liveCache["debian/trixie"] != expired {
		t.Fatal("expired entry for a still-configured layout was swept -- getLive's stale-entry fast path can no longer serve it, forcing the next request into a synchronous cold-start rebuild")
	}
}

// TestSweepExpiredLiveCacheRemovesEntryForRemovedLayout is
// TestSweepExpiredLiveCacheKeepsExpiredEntryForStillConfiguredLayout's
// counterpart: an entry for an os/codename no longer present in config at
// all (e.g. removed since the entry was built) has no getLive request path
// left to ever refresh or evict it -- sweepExpiredLiveCache is the only
// thing that ever will, so it must still do so once it has aged out.
func TestSweepExpiredLiveCacheRemovesEntryForRemovedLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	s.liveCache["ubuntu/noble"] = &liveEntry{built: time.Now().Add(-2 * liveRetiredRetention)}

	s.mu.Lock()
	s.sweepExpiredLiveCache(time.Now())
	s.mu.Unlock()

	if _, ok := s.liveCache["ubuntu/noble"]; ok {
		t.Fatal("expected the aged-out entry for a no-longer-configured layout to be swept")
	}
}

// TestSweepExpiredLiveCacheKeepsUnexpiredEntryForRemovedLayout proves the
// sweep still respects the age window for a removed layout too -- it's not
// the window that changed, only which layouts are eligible for eviction at
// all. A client that just read this generation's Release may still be
// fetching the files it names by hash, and dropping it the instant the
// layout leaves config would 404 exactly those in-flight fetches.
func TestSweepExpiredLiveCacheKeepsUnexpiredEntryForRemovedLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	fresh := &liveEntry{built: time.Now()}
	s.liveCache["ubuntu/noble"] = fresh

	s.mu.Lock()
	s.sweepExpiredLiveCache(time.Now())
	s.mu.Unlock()

	if s.liveCache["ubuntu/noble"] != fresh {
		t.Fatal("expected the recently-built entry to survive the sweep regardless of layout validity")
	}
}

// TestSweepExpiredLiveCacheAgesOutStagedEntryForRemovedLayout covers the
// staging slot, which holds a whole generation's bytes just like liveCache
// does. A layout removed from config while a generation was staged for it
// never promotes -- nothing requests it, so no promotion timer outcome
// matters -- and without this the staged bytes would sit resident for the
// life of the process.
func TestSweepExpiredLiveCacheAgesOutStagedEntryForRemovedLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	old := &liveEntry{built: time.Now().Add(-2 * liveRetiredRetention)}
	recent := &liveEntry{built: time.Now()}
	s.stagedLive["ubuntu/noble"] = &stagedLiveEntry{entry: old}
	s.stagedLive["ubuntu/jammy"] = &stagedLiveEntry{entry: recent}

	s.mu.Lock()
	s.sweepExpiredLiveCache(time.Now())
	s.mu.Unlock()

	if _, ok := s.stagedLive["ubuntu/noble"]; ok {
		t.Error("expected the aged-out staged entry for a removed layout to be swept")
	}
	if _, ok := s.stagedLive["ubuntu/jammy"]; !ok {
		t.Error("expected the recently-staged entry to survive the sweep")
	}
}

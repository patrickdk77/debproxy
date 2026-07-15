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
// single swapLiveEntry call (i.e. on every successful build for ANY layout,
// not just the one being swept). That silently defeated getLive's own
// stale-entry fast path (serve the stale entry immediately, refresh in the
// background) for any *other*, currently-configured layout that simply
// hadn't been requested recently enough to still be within its
// liveTTLBase+liveTTLJitter window -- the next request for it then fell all
// the way through to the synchronous cold-start path and blocked that
// client on a full rebuild, observed in production as repeated "building
// live cache"/"live cache built" pairs for the same os/codename long after
// startup, well after the process had been running fine.
//
// A still-configured layout's expired entry must survive the sweep --
// getLive is the one responsible for refreshing it, not this sweep.
func TestSweepExpiredLiveCacheKeepsExpiredEntryForStillConfiguredLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	expired := &liveEntry{expiry: time.Now().Add(-time.Hour)}
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
// thing that ever will, so it must still do so once the entry is expired.
func TestSweepExpiredLiveCacheRemovesEntryForRemovedLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	s.liveCache["ubuntu/noble"] = &liveEntry{expiry: time.Now().Add(-time.Hour)}

	s.mu.Lock()
	s.sweepExpiredLiveCache(time.Now())
	s.mu.Unlock()

	if _, ok := s.liveCache["ubuntu/noble"]; ok {
		t.Fatal("expected the expired entry for a no-longer-configured layout to be swept")
	}
}

// TestSweepExpiredLiveCacheKeepsUnexpiredEntryForRemovedLayout proves the
// sweep still respects expiry for a removed layout too -- it's not expiry
// that changed, only which layouts are eligible for eviction at all.
func TestSweepExpiredLiveCacheKeepsUnexpiredEntryForRemovedLayout(t *testing.T) {
	cfg := &config.Config{ResolvedLayouts: []model.Layout{{OS: "debian", Codename: "trixie"}}}
	s := New(cfg, nil, nil, nil, nil, nil, nil, nil)

	notYetExpired := &liveEntry{expiry: time.Now().Add(time.Hour)}
	s.liveCache["ubuntu/noble"] = notYetExpired

	s.mu.Lock()
	s.sweepExpiredLiveCache(time.Now())
	s.mu.Unlock()

	if s.liveCache["ubuntu/noble"] != notYetExpired {
		t.Fatal("expected the not-yet-expired entry to survive the sweep regardless of layout validity")
	}
}

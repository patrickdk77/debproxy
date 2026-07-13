package api

import (
	"context"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/valkeycache"
)

// OperationLockTTL / OperationLockRenewInterval configure the distributed
// operation lock (see OpLock). Exported so cmd/debproxy's periodic
// schedulers, which acquire the same lock this package's job queue does, use
// matching values -- one shared constant pair rather than two configs that
// could drift apart. Mirrors cmd/debproxy's own defaultLockTTL/
// defaultLockRenewInterval pair for the upstream-fetch lock: renew_interval
// must stay meaningfully smaller than TTL for "renew while a long op is in
// flight" to do anything.
const (
	OperationLockTTL           = 2 * time.Minute
	OperationLockRenewInterval = 30 * time.Second
)

// opLockPollInterval bounds how often OpLock.Acquire retries while waiting
// for a busy lock.
const opLockPollInterval = 250 * time.Millisecond

// OpLock is debproxy's global operation lock, serializing the mutating admin
// actions (snapshot, cleanup, update, rebuild, prime) against each other and
// -- when Valkey is enabled -- across every replica. Backed by
// valkeycache.AcquireLock when a Valkey client is configured, or an
// in-process channel-based mutex otherwise (safe only on a single replica;
// see NewOpLock). Callers needing the same mutual exclusion across the
// process (the async job queue's worker and cmd/debproxy's periodic
// schedulers) must share one OpLock instance -- constructing two separate
// instances over the no-Valkey fallback would each get their own,
// non-communicating in-process channel, defeating the exclusion entirely.
type OpLock struct {
	vclient valkey.Client
	keys    valkeycache.Keys
	local   chan struct{} // buffered(1); a token present means "free". nil when Valkey-backed.
}

// NewOpLock constructs an OpLock. If vclient is nil, the returned OpLock
// falls back to an in-process mutex -- correct only for a single-replica
// deployment; cross-replica coordination requires Valkey.
func NewOpLock(vclient valkey.Client, keys valkeycache.Keys) *OpLock {
	o := &OpLock{vclient: vclient, keys: keys}
	if vclient == nil {
		o.local = make(chan struct{}, 1)
		o.local <- struct{}{}
	}
	return o
}

// heldOpLock is an acquired OpLock, released via Release.
type heldOpLock struct {
	vlock *valkeycache.Lock
	local chan struct{} // non-nil (and shared with the owning OpLock) when locally backed
}

// Release drops the lock.
func (h *heldOpLock) Release(ctx context.Context) error {
	if h.vlock != nil {
		return h.vlock.Release(ctx)
	}
	h.local <- struct{}{}
	return nil
}

// StartRenewing renews the lock periodically for as long as a long-running
// operation holds it; see valkeycache.Lock.StartRenewing. The no-Valkey
// fallback has nothing to renew (an in-process channel token doesn't
// expire), so it returns a lost channel that's never closed and a no-op
// stop func.
func (h *heldOpLock) StartRenewing(ctx context.Context, ttl, interval time.Duration) (lost <-chan struct{}, stop func()) {
	if h.vlock != nil {
		return h.vlock.StartRenewing(ctx, ttl, interval)
	}
	return make(chan struct{}), func() {}
}

func (o *OpLock) acquireOnce(ctx context.Context, ttl time.Duration) (*heldOpLock, error) {
	if o.vclient != nil {
		lock, ok, err := valkeycache.AcquireLock(ctx, o.vclient, o.keys.OperationLock(), ttl)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		return &heldOpLock{vlock: lock}, nil
	}
	select {
	case <-o.local:
		return &heldOpLock{local: o.local}, nil
	default:
		return nil, nil
	}
}

// Acquire polls for the lock until it's obtained, maxWait elapses (returning
// nil, nil -- the caller's cue to report the operation as busy), or ctx is
// done. maxWait <= 0 waits indefinitely (until ctx is done) -- used by the
// async job worker, which must eventually run every queued job rather than
// give up; callers on a request path (the synchronous snapshot handler, the
// periodic schedulers) pass a short bound instead.
func (o *OpLock) Acquire(ctx context.Context, ttl, maxWait time.Duration) (*heldOpLock, error) {
	var deadline time.Time
	if maxWait > 0 {
		deadline = time.Now().Add(maxWait)
	}
	for {
		held, err := o.acquireOnce(ctx, ttl)
		if err != nil {
			return nil, err
		}
		if held != nil {
			return held, nil
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, nil
		}
		select {
		case <-time.After(opLockPollInterval):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

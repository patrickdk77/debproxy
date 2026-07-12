package valkeycache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Lock is a held distributed lock. The zero value is not usable; obtain one
// via AcquireLock.
type Lock struct {
	v     valkey.Client
	key   string
	token string
}

// renewLockScript extends key's TTL only if its value still matches token,
// so a replica can never renew a lock it no longer holds. Uses PEXPIRE
// (milliseconds) rather than EXPIRE so sub-second TTLs -- used by tests to
// keep lock-expiry scenarios fast -- don't get truncated to 0 and rejected.
var renewLockScript = valkey.NewLuaScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
	return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
`)

// releaseLockScript deletes key only if its value still matches token, so a
// replica can never release a lock it no longer holds (e.g. after its TTL
// expired and another replica already acquired it).
var releaseLockScript = valkey.NewLuaScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
	return redis.call('DEL', KEYS[1])
end
return 0
`)

// AcquireLock attempts to acquire the named lock for ttl using SET NX EX,
// which is already atomic and needs no script. ok is false (with a nil
// error) when another replica already holds the lock -- the expected,
// common outcome for a fetch lock, not a failure.
func AcquireLock(ctx context.Context, v valkey.Client, key string, ttl time.Duration) (lock *Lock, ok bool, err error) {
	token, err := newLockToken()
	if err != nil {
		return nil, false, fmt.Errorf("generate lock token: %w", err)
	}
	err = v.Do(ctx, v.B().Set().Key(key).Value(token).Nx().Px(ttl).Build()).Error()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("acquire lock %s: %w", key, err)
	}
	return &Lock{v: v, key: key, token: token}, true, nil
}

// Renew extends the lock's TTL to ttl, but only if this Lock still holds it.
// ok is false if another replica has since acquired the lock (this process
// stalled past its TTL) -- the caller must then treat the in-flight work as
// no longer exclusive.
func (l *Lock) Renew(ctx context.Context, ttl time.Duration) (ok bool, err error) {
	millis := ttl.Milliseconds()
	if millis <= 0 {
		millis = 1
	}
	resp := renewLockScript.Exec(ctx, l.v, []string{l.key}, []string{l.token, strconv.FormatInt(millis, 10)})
	n, err := resp.AsInt64()
	if err != nil {
		return false, fmt.Errorf("renew lock %s: %w", l.key, err)
	}
	return n == 1, nil
}

// Release drops the lock, but only if this Lock still holds it. Safe to call
// even if the lock already expired or was taken over by another replica.
func (l *Lock) Release(ctx context.Context) error {
	resp := releaseLockScript.Exec(ctx, l.v, []string{l.key}, []string{l.token})
	if _, err := resp.AsInt64(); err != nil {
		return fmt.Errorf("release lock %s: %w", l.key, err)
	}
	return nil
}

// StartRenewing renews the lock every interval (with the same ttl each time)
// until stop is called or the lock is found to be lost. lost is closed the
// moment a renew reports the lock is no longer held, so a caller running a
// long upstream fetch can abort rather than publish results under a false
// assumption of exclusivity. Renew errors (as opposed to a clean loss) are
// logged and retried on the next tick rather than treated as loss, since a
// transient Valkey error is not evidence another replica took over.
func (l *Lock) StartRenewing(ctx context.Context, ttl, interval time.Duration) (lost <-chan struct{}, stop func()) {
	lostCh := make(chan struct{})
	done := make(chan struct{})
	stopCh := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				ok, err := l.Renew(ctx, ttl)
				if err != nil {
					slog.Warn("lock renew failed", "key", l.key, "err", err)
					continue
				}
				if !ok {
					close(lostCh)
					return
				}
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return lostCh, func() {
		close(stopCh)
		<-done
	}
}

func newLockToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(b)), nil
}

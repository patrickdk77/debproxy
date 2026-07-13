package valkeycache

import (
	"context"
	"log/slog"
	"time"

	"github.com/valkey-io/valkey-go"
)

// ChannelLiveUpdated carries only a small notification; the actual content
// always lives in a regular Valkey key, never in the pub/sub payload itself,
// and it's explicitly an optimization layered on top of a polling
// reconciliation path (each replica's own liveCache TTL) -- a missed message
// is never a permanent miss.
const ChannelLiveUpdated = "events:live-updated"

// ChannelSnapshotPublished notifies every replica that a new snapshot was
// published and "current/*" therefore changed underneath them, so each can
// purge its own storage file cache's "current/" entries (see
// internal/storage/filecache.Purger) -- the replica that actually ran the
// snapshot already self-invalidates the exact paths it wrote and doesn't
// need this notice itself. Carries no payload: the action is always the
// same generic "purge current/", never anything path- or replica-specific.
// Fire-and-forget like ChannelLiveUpdated: a missed message just means a
// stale "current/*" entry lives out its natural LRU lifetime instead of
// being purged immediately, not a correctness failure, since a specific
// dated snapshot's own paths are still immutable and always correct.
const ChannelSnapshotPublished = "events:snapshot-published"

// Publish publishes msg (typically a small JSON payload) on channel.
// Fire-and-forget by design: callers should log a Publish error and continue
// rather than fail the write that triggered it, since every consumer also
// has a polling fallback that doesn't depend on this message arriving.
func Publish(ctx context.Context, v valkey.Client, channel, msg string) error {
	return v.Do(ctx, v.B().Publish().Channel(channel).Message(msg).Build()).Error()
}

// Subscribe subscribes to channel and calls onMessage for each message
// received. It blocks until ctx is done, reconnecting with a short backoff
// if the subscription drops (Receive returns before ctx is done for any
// reason other than a clean unsubscribe, which normal use of this function
// never triggers). Callers should run it in its own goroutine and treat it
// as a best-effort accelerator: it never returns before ctx is canceled, but
// consumers must not rely on it for correctness -- pair every subscription
// with the reconciliation poll described in the design doc.
//
// Receive runs inside v.Dedicated() rather than being called directly on v:
// per valkey-go's own README ("Pub/Sub" section), a plain v.Receive() shares
// its connection with v's regular auto-pipelined command traffic, and a
// long-lived subscription sharing a connection with heavy concurrent command
// load is exactly the documented scenario the library recommends Dedicated()
// for. This one process observed that combination panic in production
// (valkey-go's pipe reader hit its "protocol bug, message handled out of
// order" invariant -- an unrecoverable, same-goroutine-only Go panic that
// crashed the whole process, since that reader goroutine is spawned inside
// the library, outside any stack frame debproxy could recover() from).
// Dedicated() reserves one connection exclusively for this subscription's
// entire lifetime, never interleaved with any other command, removing the
// condition that produced it.
func Subscribe(ctx context.Context, v valkey.Client, channel string, onMessage func(valkey.PubSubMessage)) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for ctx.Err() == nil {
		err := v.Dedicated(func(c valkey.DedicatedClient) error {
			return c.Receive(ctx, c.B().Subscribe().Channel(channel).Build(), onMessage)
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("valkey subscription dropped, reconnecting", "channel", channel, "err", err, "retry_in", backoff)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

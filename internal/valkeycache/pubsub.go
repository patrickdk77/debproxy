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
func Subscribe(ctx context.Context, v valkey.Client, channel string, onMessage func(valkey.PubSubMessage)) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for ctx.Err() == nil {
		err := v.Receive(ctx, v.B().Subscribe().Channel(channel).Build(), onMessage)
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

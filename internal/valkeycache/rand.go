package valkeycache

import (
	"math/rand"
	"time"
)

// RandDuration returns a random duration in [0, max). max <= 0 returns 0
// (rand.Int63n panics on a non-positive argument). Shared by every
// refresh/TTL jitter calculation that coordinates with this package's
// claim/lock TTLs (cmd/debproxy's refresh loops, internal/server's live
// artifact TTL) so they all draw jitter the same way.
func RandDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max)))
}

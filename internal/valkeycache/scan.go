package valkeycache

import (
	"context"

	"github.com/valkey-io/valkey-go"
)

// ScanSetMemberCount hints how many members SSCAN returns per round trip.
const ScanSetMemberCount = 1000

// ScanSetMembers walks key's full SET membership via SSCAN, in batches of
// ScanSetMemberCount, and returns every member. Used instead of SMEMBERS so a
// single reply is never unbounded regardless of the set's size -- some
// buckets (e.g. Ubuntu's "universe" component, or the global upstream-state
// registry across a large mirror) run to tens of thousands of members.
func ScanSetMembers(ctx context.Context, v valkey.Client, key string) ([]string, error) {
	var members []string
	cursor := uint64(0)
	for {
		entry, err := v.Do(ctx, v.B().Sscan().Key(key).Cursor(cursor).Count(ScanSetMemberCount).Build()).AsScanEntry()
		if err != nil {
			return nil, err
		}
		members = append(members, entry.Elements...)
		cursor = entry.Cursor
		if cursor == 0 {
			break
		}
	}
	return members, nil
}

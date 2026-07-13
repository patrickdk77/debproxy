package valkeycache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/valkey-io/valkey-go"
)

// GetJSON reads key and JSON-decodes it into a new T. ok is false with a nil
// error on a clean cache miss (key doesn't exist) -- callers distinguish
// "doesn't exist" from "lookup failed" via ok, not by inspecting err.
func GetJSON[T any](ctx context.Context, v valkey.Client, key string) (val *T, ok bool, err error) {
	str, err := v.Do(ctx, v.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var out T
	if err := json.Unmarshal([]byte(str), &out); err != nil {
		return nil, false, err
	}
	return &out, true, nil
}

// SetJSON JSON-encodes val and writes it to key with a plain SET (no TTL).
func SetJSON(ctx context.Context, v valkey.Client, key string, val any) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return v.Do(ctx, v.B().Set().Key(key).Value(string(data)).Build()).Error()
}

// SetJSONEx is SetJSON with a TTL (PX, milliseconds) attached, for values
// that should expire on their own rather than live forever (e.g. async job
// status records).
func SetJSONEx(ctx context.Context, v valkey.Client, key string, val any, ttl time.Duration) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return v.Do(ctx, v.B().Set().Key(key).Value(string(data)).Px(ttl).Build()).Error()
}

// MGetJSON MGETs keys and JSON-decodes each value into a T. results[i] is
// the zero value and ok[i] is false wherever keys[i] was missing *or* failed
// to decode -- both are silently skipped, never returned as err. Use this
// when a value that came back malformed should be treated exactly like a
// value that was never written (the caller doesn't need to distinguish
// "missing" from "corrupt"). Callers that need positional correlation (e.g.
// which arch or relpath a value belongs to) can index results/ok by i.
func MGetJSON[T any](ctx context.Context, v valkey.Client, keys []string) (results []T, ok []bool, err error) {
	if len(keys) == 0 {
		return nil, nil, nil
	}
	vals, err := v.Do(ctx, v.B().Mget().Key(keys...).Build()).ToArray()
	if err != nil {
		return nil, nil, err
	}
	results = make([]T, len(vals))
	ok = make([]bool, len(vals))
	for i, rv := range vals {
		str, serr := rv.ToString()
		if serr != nil {
			continue
		}
		if uerr := json.Unmarshal([]byte(str), &results[i]); uerr != nil {
			continue
		}
		ok[i] = true
	}
	return results, ok, nil
}

// MGetJSONStrict is MGetJSON's counterpart for callers that must not treat
// corrupt data the same as absent data: a missing key (or one that vanished
// between an earlier SMEMBERS/SCAN and this MGET -- an expected, harmless
// race) is silently skipped, exactly like MGetJSON, but a value that exists
// and fails to decode returns an error immediately, since that indicates
// real data corruption worth surfacing rather than silently dropping a
// record from a listing.
func MGetJSONStrict[T any](ctx context.Context, v valkey.Client, keys []string) ([]T, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	vals, err := v.Do(ctx, v.B().Mget().Key(keys...).Build()).ToArray()
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(vals))
	for _, rv := range vals {
		str, serr := rv.ToString()
		if serr != nil {
			continue // vanished between listing and MGET; skip
		}
		var val T
		if uerr := json.Unmarshal([]byte(str), &val); uerr != nil {
			return nil, uerr
		}
		out = append(out, val)
	}
	return out, nil
}

// MGetBatchSize bounds how many keys MGetJSONStrictBatched sends per MGET.
const MGetBatchSize = 1000

// MGetJSONStrictBatched is MGetJSONStrict, but sent in chunks of at most
// MGetBatchSize keys per round trip, so no single reply is ever unbounded by
// len(keys) -- a listing over a bucket with tens of thousands of entries
// would otherwise produce one multi-hundred-MB MGET reply.
func MGetJSONStrictBatched[T any](ctx context.Context, v valkey.Client, keys []string) ([]T, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	out := make([]T, 0, len(keys))
	for i := 0; i < len(keys); i += MGetBatchSize {
		batch := keys[i:min(i+MGetBatchSize, len(keys))]
		vals, err := MGetJSONStrict[T](ctx, v, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, vals...)
	}
	return out, nil
}

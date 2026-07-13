package upstream

import (
	"context"
	"strings"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/valkeycache"
)

// upstreamPkgBatchSize bounds how many entries a single MGET (read), MSET
// (write), SADD, SREM, or DEL request covers, so no single Valkey
// reply/request for a large arch is ever bounded only by the arch's total
// package count.
const upstreamPkgBatchSize = 1000

// upstreamPkgMember encodes a package+version as one bucket-set member,
// matching valkeystore's bucketMember convention exactly (including its
// SplitN(_, ":", 2)-based reversal below, which is what makes this safe for a
// version containing its own ":" -- Debian epoch versions look like
// "1:2.3-1" -- since Debian package names themselves never contain ":", the
// first colon in the member is always the pkg/version boundary).
//
// Identity here is deliberately just pkg+version, not also the stanza's
// content hash: a well-formed Debian archive guarantees identical
// package+version implies identical content (that's what the Release file's
// own SHA256 verification already assumes elsewhere in this codebase), so
// this diff-by-membership approach cannot miss a real content change without
// upstream itself violating that guarantee.
func upstreamPkgMember(pkg, version string) string {
	return pkg + ":" + version
}

func splitUpstreamPkgMember(m string) (pkg, version string, ok bool) {
	parts := strings.SplitN(m, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// scanBucketMembers walks bucket's full membership via SSCAN and returns
// every member. Used instead of SMEMBERS so a single reply is never
// unbounded regardless of the bucket's size. Thin wrapper over the shared
// valkeycache helper (also used by internal/metadata/valkeystore for the
// same reason) so this package's call sites don't need to change.
func scanBucketMembers(ctx context.Context, v valkey.Client, bucket string) ([]string, error) {
	return valkeycache.ScanSetMembers(ctx, v, bucket)
}

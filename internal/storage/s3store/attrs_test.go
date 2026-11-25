package s3store

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// A first-party repository published by debrepo lives straight under the
// prefix, so its indexes change in place and must not be marked immutable.
func TestPutAttrsByPath(t *testing.T) {
	cases := []struct {
		path         string
		acl          types.ObjectCannedACL
		cacheControl string
	}{
		{"dists/trixie/InRelease", types.ObjectCannedACLPublicRead, "public, max-age=720"},
		{"dists/trixie/main/binary-amd64/Packages.gz", types.ObjectCannedACLPublicRead, "public, max-age=720"},
		{"dists/trixie/main/.debrepo.old.zst", types.ObjectCannedACLPublicRead, "public, max-age=720"},
		{"pool/main/.debrepo.zst", types.ObjectCannedACLPublicRead, "public, max-age=31536000, immutable"},
		{"current/debian/dists/trixie/InRelease", types.ObjectCannedACLPublicRead, "public, max-age=720"},
		{"pool/main/h/hello/hello_1.0_amd64.deb", types.ObjectCannedACLPublicRead, "public, max-age=31536000, immutable"},
		{"metadata/index", "", ""},
	}
	for _, tc := range cases {
		acl, cacheControl, _ := s3PutAttrs(tc.path)
		if acl != tc.acl || cacheControl != tc.cacheControl {
			t.Errorf("%s: acl %q cache-control %q, want %q and %q", tc.path, acl, cacheControl, tc.acl, tc.cacheControl)
		}
	}
}

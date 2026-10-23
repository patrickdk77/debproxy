package avail

import (
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/model"
)

// The GitHub CLI repository publishes "Section: " with an empty value.
// Concatenating that into the pool path produced an empty segment, which
// Go's mux redirected away and nothing then matched: the package 502ed
// through debproxy and the stored key would have carried a literal "//".
func TestPoolPathFromFilenameBlankSection(t *testing.T) {
	for _, section := range []string{"", " ", "\t"} {
		got := poolPathFromFilename("debian", "trixie", "github", section, "gh", "pool/main/g/gh/gh_2.103.0_amd64.deb")
		if strings.Contains(got, "//") {
			t.Errorf("section %q: empty path segment in %q", section, got)
		}
		want := "pool/debian/trixie/github/misc/g/gh/gh_2.103.0_amd64.deb"
		if got != want {
			t.Errorf("section %q: got %q, want %q", section, got, want)
		}
	}
}

// Both builders must name the same file, or a path computed one way can
// never find a file stored the other way.
func TestPoolPathBuildersAgree(t *testing.T) {
	for _, section := range []string{"", "utils", " net "} {
		a := poolPathFromFilename("debian", "trixie", "up", section, "foo", "pool/x/foo_1.0-1_amd64.deb")
		b := model.PoolPath("debian", "trixie", "up", section, "foo", "1.0-1", "amd64")
		if a != b {
			t.Errorf("section %q: poolPathFromFilename=%q model.PoolPath=%q", section, a, b)
		}
	}
}

func TestPoolPathFromFilenameKeepsRealSection(t *testing.T) {
	got := poolPathFromFilename("debian", "trixie", "up", "utils", "foo", "pool/main/f/foo/foo_1.0_amd64.deb")
	if got != "pool/debian/trixie/up/utils/f/foo/foo_1.0_amd64.deb" {
		t.Fatalf("got %q", got)
	}
}

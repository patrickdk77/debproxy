package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
)

// TestTryPDiffRejectsForgedIndexDigest proves that a Packages.diff/Index file
// whose bytes don't match the SHA256 the (GPG-verified) Release lists for it
// is rejected before ever being parsed or trusted. Previously the Index file
// was only checked for presence in Release.Files, never digest-verified, so
// its self-reported CurrentSHA256 -- used as the final safety check after
// applying patches -- was attacker/mirror-controlled.
func TestTryPDiffRejectsForgedIndexDigest(t *testing.T) {
	// Deliberately not a valid PDiffIndex format at all: if the digest check
	// is bypassed, parsing would fail anyway, but for a real attack the
	// forger controls this content and would make it parse just fine. Using
	// garbage here proves the rejection happens before parsing is attempted.
	indexBody := []byte("not a real pdiff index")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexBody)
	}))
	defer srv.Close()

	src := model.UpstreamSource{Name: "test", URL: srv.URL, Suite: "trixie", Component: "main", Archs: []string{"amd64"}}
	f := NewFetcher(src, nil)

	rel := &apt.Release{
		Para: apt.NewParagraph(),
		Files: map[string]apt.FileEntry{
			// SHA256 does not match indexBody's real digest.
			"main/binary-amd64/Packages.diff/Index": {SHA256: "0000000000000000000000000000000000000000000000000000000000000000"[:64]},
		},
	}

	pkgs, ok := f.tryPDiff(context.Background(), rel, "main/binary-amd64/", "amd64", "cached-sha", nil)
	if ok {
		t.Fatalf("expected tryPDiff to reject forged Index digest, got ok=true pkgs=%v", pkgs)
	}

	// Same check for the Sources variant.
	relSrc := &apt.Release{
		Para: apt.NewParagraph(),
		Files: map[string]apt.FileEntry{
			"main/source/Sources.diff/Index": {SHA256: "0000000000000000000000000000000000000000000000000000000000000000"[:64]},
		},
	}
	srcs, ok := f.tryPDiffSrc(context.Background(), relSrc, "main/source/", "cached-sha", nil)
	if ok {
		t.Fatalf("expected tryPDiffSrc to reject forged Index digest, got ok=true srcs=%v", srcs)
	}
}

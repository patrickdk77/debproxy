package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestVerifyByHashAcceptsMatchingContent(t *testing.T) {
	data := []byte("Package: hello\n")
	if err := verifyByHash(data, sha(data)); err != nil {
		t.Fatalf("matching content rejected: %v", err)
	}
}

func TestVerifyByHashIsCaseInsensitive(t *testing.T) {
	data := []byte("x")
	if err := verifyByHash(data, strings.ToUpper(sha(data))); err != nil {
		t.Fatalf("uppercase hash rejected: %v", err)
	}
}

// TestVerifyByHashRejectsSubstitutedContent is the regression test for
// unverified peer fetches: a 200 from whatever now owns a reused peer
// address must not be staged as the index.
func TestVerifyByHashRejectsSubstitutedContent(t *testing.T) {
	want := sha([]byte("Package: hello\n"))
	for _, body := range [][]byte{
		[]byte("<html>catch-all app</html>"),
		[]byte(""),
		[]byte("Package: hello\n "),
	} {
		if err := verifyByHash(body, want); err == nil {
			t.Errorf("%q accepted under a hash it does not match", body)
		}
	}
}

func TestVerifyByHashRejectsEmptyHash(t *testing.T) {
	if err := verifyByHash([]byte("x"), ""); err == nil {
		t.Fatal("empty expected hash accepted")
	}
}

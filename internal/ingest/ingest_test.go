package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/debproxy/debproxy/internal/upstream"
)

func TestExistsCacheAddHasRemove(t *testing.T) {
	c := &ExistsCache{}

	if c.Has("pool/a") {
		t.Error("Has on empty cache = true, want false")
	}

	c.Add("pool/a")
	if !c.Has("pool/a") {
		t.Error("Has after Add = false, want true")
	}

	c.Remove("pool/a")
	if c.Has("pool/a") {
		t.Error("Has after Remove = true, want false")
	}
}

// TestExistsCacheRemoveUnknownPathIsNoop is the bad-data counterpart to the
// happy-path add/remove test: Remove is called by pullThrough on every
// pull-through request, most of which never had a stale (or any) cache entry
// in the first place -- it must not panic or otherwise misbehave just
// because there was nothing to clear.
func TestExistsCacheRemoveUnknownPathIsNoop(t *testing.T) {
	c := &ExistsCache{}
	c.Remove("pool/never-added")
	if c.Has("pool/never-added") {
		t.Error("Has after removing an unknown path = true, want false")
	}
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestDigestVerifyingReaderCorrectDigestPassesThrough is the happy path: a
// stream whose content matches expectedSHA256 reads through cleanly (real
// io.EOF at the end, no error), and every byte read also lands in the
// client-side writer -- proving the tee actually tees.
func TestDigestVerifyingReaderCorrectDigestPassesThrough(t *testing.T) {
	content := []byte("the quick brown fox jumps over the lazy dog")
	var client bytes.Buffer
	dvr := newDigestVerifyingReader(bytes.NewReader(content), &client, sha256hex(content))

	got, err := io.ReadAll(dvr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("read content = %q, want %q", got, content)
	}
	if !bytes.Equal(client.Bytes(), content) {
		t.Errorf("client tee received %q, want %q", client.Bytes(), content)
	}
}

// TestDigestVerifyingReaderMismatchReturnsErrorInsteadOfEOF is the direct
// regression test for the safety property this type exists for: storage's
// own atomic write (a temp file + rename, or an all-or-nothing PUT) commits
// on a clean io.EOF and aborts/cleans up on any other error, so a corrupt
// download must surface as a real error at the point EOF would otherwise be
// returned, not silently pass through.
func TestDigestVerifyingReaderMismatchReturnsErrorInsteadOfEOF(t *testing.T) {
	content := []byte("actual upstream content")
	dvr := newDigestVerifyingReader(bytes.NewReader(content), nil, sha256hex([]byte("something else entirely")))

	_, err := io.ReadAll(dvr)
	if err == nil {
		t.Fatal("expected a digest-mismatch error, got nil (EOF passed through uncaught)")
	}
	if !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("error = %v, want it to wrap upstream.ErrDigestMismatch", err)
	}
}

// TestDigestVerifyingReaderClientWriteFailureIsBestEffort proves a broken
// client connection never aborts the underlying read -- the whole point of
// streaming to a live client is service to that client, not a precondition
// for the download that populates the cache for everyone else.
func TestDigestVerifyingReaderClientWriteFailureIsBestEffort(t *testing.T) {
	content := []byte("content that must still be fully read and hashed")
	dvr := newDigestVerifyingReader(bytes.NewReader(content), alwaysFailWriter{}, sha256hex(content))

	got, err := io.ReadAll(dvr)
	if err != nil {
		t.Fatalf("ReadAll: %v (a client write failure must not abort the read)", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("read content = %q, want %q", got, content)
	}
}

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }

package upstream

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestUpstreamRelPathAcceptsNormalFilenames(t *testing.T) {
	cases := map[string]string{
		"pool/main/h/hello/hello_1.0_amd64.deb":  "pool/main/h/hello/hello_1.0_amd64.deb",
		"/pool/main/h/hello/hello_1.0_amd64.deb": "pool/main/h/hello/hello_1.0_amd64.deb",
		"pool/main/./h/hello.deb":                "pool/main/h/hello.deb",
	}
	for in, want := range cases {
		got, err := upstreamRelPath(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// TestUpstreamRelPathRejectsURLDelimiters covers the two characters that
// would change what the joined URL means: "?" turns the tail into a
// query string, "#" into a fragment the client never sends.
func TestUpstreamRelPathRejectsURLDelimiters(t *testing.T) {
	for _, in := range []string{
		"pool/x.deb?token=1",
		"pool/x.deb#frag",
		"?",
		"pool/a?b#c",
	} {
		if _, err := upstreamRelPath(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestUpstreamRelPathRejectsTraversalAndEmpty(t *testing.T) {
	for _, in := range []string{"../etc/passwd", "pool/../../x", "", "/", "x\x00y"} {
		if _, err := upstreamRelPath(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// TestBoundedReaderPassesSmallInputThrough is the happy path: data under
// the cap arrives unchanged with a clean EOF.
func TestBoundedReaderPassesSmallInputThrough(t *testing.T) {
	src := strings.Repeat("x", 4096)
	got, err := io.ReadAll(boundedReader(strings.NewReader(src)))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != src {
		t.Errorf("content altered: %d bytes, want %d", len(got), len(src))
	}
}

// TestBoundedReaderErrorsPastCap is the regression test. The important
// property is the error type: a plain io.LimitReader would return EOF at
// the cap and a deb822 parser would treat the truncated prefix as the
// whole index.
func TestBoundedReaderErrorsPastCap(t *testing.T) {
	// An endless stream of newlines; the reader must stop it with
	// errIndexTooLarge rather than EOF.
	endless := &repeatReader{b: '\n'}
	n, err := io.Copy(io.Discard, boundedReader(endless))
	if !errors.Is(err, errIndexTooLarge) {
		t.Fatalf("err = %v, want errIndexTooLarge", err)
	}
	if n < maxDecompressedIndexBytes || n > maxDecompressedIndexBytes+1 {
		t.Errorf("stopped after %d bytes, want ~%d", n, maxDecompressedIndexBytes)
	}
}

// TestBoundedReaderExactlyAtCapIsClean guards the boundary: a stream of
// precisely the cap's length is legal and must end with EOF, not error.
func TestBoundedReaderExactlyAtCapIsClean(t *testing.T) {
	exact := &repeatReader{b: 'a', limit: maxDecompressedIndexBytes}
	n, err := io.Copy(io.Discard, boundedReader(exact))
	if err != nil {
		t.Fatalf("err = %v for an input exactly at the cap", err)
	}
	if n != maxDecompressedIndexBytes {
		t.Errorf("read %d, want %d", n, maxDecompressedIndexBytes)
	}
}

func TestBoundedReaderOneOverCapErrors(t *testing.T) {
	over := &repeatReader{b: 'a', limit: maxDecompressedIndexBytes + 1}
	_, err := io.Copy(io.Discard, boundedReader(over))
	if !errors.Is(err, errIndexTooLarge) {
		t.Fatalf("err = %v, want errIndexTooLarge for cap+1", err)
	}
}

// TestBoundedReaderPropagatesUnderlyingError confirms the wrapper does
// not mask a real read failure from the source.
func TestBoundedReaderPropagatesUnderlyingError(t *testing.T) {
	want := errors.New("disk on fire")
	r := boundedReader(io.MultiReader(bytes.NewReader([]byte("ok")), &errReader{err: want}))
	_, err := io.ReadAll(r)
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want the source error", err)
	}
}

// repeatReader yields byte b forever, or up to limit bytes when limit > 0.
type repeatReader struct {
	b     byte
	limit int64
	n     int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.limit > 0 {
		remaining := r.limit - r.n
		if remaining <= 0 {
			return 0, io.EOF
		}
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	for i := range p {
		p[i] = r.b
	}
	r.n += int64(len(p))
	return len(p), nil
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

package apt

import (
	"bytes"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const sample = "Package: hello\nVersion: 1.0\nFilename: pool/h/hello_1.0.deb\n\n"

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zstdBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := zstd.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func xzBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := xz.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestOpenCompressedDecodesEveryIndexForm(t *testing.T) {
	cases := map[string][]byte{
		"Packages":     []byte(sample),
		"Packages.gz":  gzipBytes(t, sample),
		"Packages.zst": zstdBytes(t, sample),
		"Packages.xz":  xzBytes(t, sample),
	}
	for name, data := range cases {
		rc, err := OpenCompressed(name, bytes.NewReader(data))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Errorf("%s: read: %v", name, err)
			continue
		}
		if string(got) != sample {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

// TestOpenCompressedRejectsCorruptInput covers each decoder's error path:
// garbage under a compressed suffix must surface as an error at open or
// at first read, never as silently empty output.
func TestOpenCompressedRejectsCorruptInput(t *testing.T) {
	garbage := []byte("this is not compressed data at all")
	for _, name := range []string{"Packages.gz", "Packages.zst", "Packages.xz"} {
		rc, err := OpenCompressed(name, bytes.NewReader(garbage))
		if err != nil {
			continue // rejected at open: fine
		}
		_, err = io.ReadAll(rc)
		rc.Close()
		if err == nil {
			t.Errorf("%s: corrupt input decoded without error", name)
		}
	}
}

func TestOpenCompressedUnknownSuffixPassesThrough(t *testing.T) {
	rc, err := OpenCompressed("Release", strings.NewReader("plain"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if string(got) != "plain" {
		t.Errorf("got %q", got)
	}
}

// TestOpenCompressedZstdCloseReleasesGoroutines is the regression test for
// the leak: *zstd.Decoder is not an io.Closer, so code that type-asserts
// and defers Close never releases its workers. OpenCompressed's wrapper
// must.
func TestOpenCompressedZstdCloseReleasesGoroutines(t *testing.T) {
	data := zstdBytes(t, sample)
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		rc, err := OpenCompressed("Packages.zst", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		// Abandon the read partway, as a parser that hits an error would.
		buf := make([]byte, 4)
		_, _ = rc.Read(buf)
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Give any lingering workers a moment to exit before counting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("goroutines before=%d after=%d; zstd decoders leaked",
		before, runtime.NumGoroutine())
}

func TestZstdDecoderIsNotAnIOCloser(t *testing.T) {
	// Documents the fact the wrapper exists for; if the library ever adds
	// an error-returning Close this becomes removable.
	d, _ := zstd.NewReader(nil)
	defer d.Close()
	if _, ok := any(d).(io.Closer); ok {
		t.Log("*zstd.Decoder now implements io.Closer; zstdCloser is redundant")
	}
}

func TestStripIndexSuffix(t *testing.T) {
	cases := map[string]string{
		"Packages":        "Packages",
		"Packages.gz":     "Packages",
		"Packages.zst":    "Packages",
		"Packages.xz":     "Packages",
		"Sources.gz":      "Sources",
		"Release":         "Release",
		"a/b/Packages.gz": "a/b/Packages",
	}
	for in, want := range cases {
		if got := StripIndexSuffix(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

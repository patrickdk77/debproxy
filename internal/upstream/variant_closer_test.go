package upstream

import (
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func zstdPayload(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := zstd.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Package: x\n\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestZstdVariantsReturnACloser is the regression test for the decoder
// leak: the fetch loop closes a variant's reader only if it satisfies
// io.Closer, and the bare *zstd.Decoder never did, so its goroutines were
// never released.
func TestZstdVariantsReturnACloser(t *testing.T) {
	data := zstdPayload(t)
	for _, set := range [][]pkgVariant{pkgVariants, srcVariants} {
		for _, v := range set {
			if v.ext != "Packages.zst" && v.ext != "Sources.zst" {
				continue
			}
			r, err := v.decomp(data)
			if err != nil {
				t.Fatalf("%s: %v", v.ext, err)
			}
			rc, ok := r.(io.Closer)
			if !ok {
				t.Fatalf("%s: reader does not implement io.Closer; decoder will leak", v.ext)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("%s: read: %v", v.ext, err)
			}
			if string(got) != "Package: x\n\n" {
				t.Fatalf("%s: got %q", v.ext, got)
			}
			if err := rc.Close(); err != nil {
				t.Fatalf("%s: close: %v", v.ext, err)
			}
		}
	}
}

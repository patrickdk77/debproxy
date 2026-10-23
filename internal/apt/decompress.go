package apt

import (
	"compress/bzip2"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// IndexSuffixes lists the compressed forms an index file may be published
// in, in the order a reader should prefer them: zstd decodes fastest, gzip
// is universal, xz is slowest. The empty string is the plain file and
// sorts first because it needs no decoding at all.
var IndexSuffixes = []string{"", ".zst", ".gz", ".xz"}

// OpenCompressed wraps r with the decoder its name's suffix calls for and
// returns a reader that yields the plain bytes. Names with no recognized
// suffix are returned as-is. The caller must Close the result; for zstd
// that is what releases the decoder's worker goroutines, and nothing else
// does, because *zstd.Decoder does not satisfy io.Closer and a type
// assertion on it silently never fires.
func OpenCompressed(name string, r io.Reader) (io.ReadCloser, error) {
	switch {
	case strings.HasSuffix(name, ".zst"):
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("zstd %s: %w", name, err)
		}
		return zstdCloser{zr}, nil
	case strings.HasSuffix(name, ".gz"):
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip %s: %w", name, err)
		}
		return gr, nil
	case strings.HasSuffix(name, ".xz"):
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("xz %s: %w", name, err)
		}
		return io.NopCloser(xr), nil
	case strings.HasSuffix(name, ".bz2"):
		return io.NopCloser(bzip2.NewReader(r)), nil
	default:
		return io.NopCloser(r), nil
	}
}

// zstdCloser adapts *zstd.Decoder, whose Close returns nothing, to
// io.Closer.
type zstdCloser struct{ *zstd.Decoder }

func (z zstdCloser) Close() error {
	z.Decoder.Close()
	return nil
}

// StripIndexSuffix returns name without any recognized compression suffix,
// so "Packages.gz" and "Packages" compare equal as the same index.
func StripIndexSuffix(name string) string {
	for _, s := range IndexSuffixes[1:] {
		if strings.HasSuffix(name, s) {
			return strings.TrimSuffix(name, s)
		}
	}
	return name
}

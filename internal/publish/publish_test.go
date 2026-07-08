package publish_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/debproxy/debproxy/internal/publish"
)

// fakeSink is an in-memory FileSink that records every write.
type fakeSink struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newFakeSink() *fakeSink {
	return &fakeSink{files: map[string][]byte{}}
}

func (s *fakeSink) WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.files[relPath] = data
	s.mu.Unlock()
	return nil
}

const testStanza = "Package: hello\nVersion: 1.0\nArchitecture: amd64\n\n"

func generate(t *testing.T, comp publish.Compression) map[string][]byte {
	t.Helper()
	sink := newFakeSink()
	in := publish.SuiteInput{
		OS:            "debian",
		Codename:      "trixie",
		Suite:         "trixie",
		Architectures: []string{"amd64"},
		Components:    []string{"main"},
		Stanzas: map[string]map[string][]string{
			"main": {"amd64": {testStanza}},
		},
		Compression: comp,
	}
	if err := publish.GenerateSuite(context.Background(), sink, "root", in, nil); err != nil {
		t.Fatalf("GenerateSuite: %v", err)
	}
	return sink.files
}

const (
	relGz  = "root/dists/trixie/main/binary-amd64/Packages.gz"
	relZst = "root/dists/trixie/main/binary-amd64/Packages.zst"
	relXz  = "root/dists/trixie/main/binary-amd64/Packages.xz"
)

// TestGenerateSuite_GZipLevels proves gzip is skipped when disabled (0) and,
// for every level 1-9, produces a valid .gz file that decompresses back to
// the exact original content.
func TestGenerateSuite_GZipLevels(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		files := generate(t, publish.Compression{GZip: 0})
		if _, ok := files[relGz]; ok {
			t.Error("GZip: 0 should not produce a .gz file")
		}
	})

	for level := 1; level <= 9; level++ {
		level := level
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			files := generate(t, publish.Compression{GZip: level})
			data, ok := files[relGz]
			if !ok {
				t.Fatalf("GZip: %d should produce a .gz file", level)
			}
			gr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("level %d: not valid gzip: %v", level, err)
			}
			got, err := io.ReadAll(gr)
			if err != nil {
				t.Fatalf("level %d: decompress failed: %v", level, err)
			}
			if string(got) != testStanza {
				t.Fatalf("level %d: round-trip mismatch: got %q want %q", level, got, testStanza)
			}
		})
	}
}

// TestGenerateSuite_ZStdLevels proves zstd is skipped when disabled (0) and,
// for every level 1-9, produces a valid .zst file that decompresses back to
// the exact original content -- exercising zstd.EncoderLevelFromZstd's
// best-match bucketing (raw levels 1-9 map onto 4 internal presets) for the
// whole range, not just a single sample level.
func TestGenerateSuite_ZStdLevels(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		files := generate(t, publish.Compression{ZStd: 0})
		if _, ok := files[relZst]; ok {
			t.Error("ZStd: 0 should not produce a .zst file")
		}
	})

	for level := 1; level <= 9; level++ {
		level := level
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			files := generate(t, publish.Compression{ZStd: level})
			data, ok := files[relZst]
			if !ok {
				t.Fatalf("ZStd: %d should produce a .zst file", level)
			}
			zr, err := zstd.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("level %d: not valid zstd: %v", level, err)
			}
			defer zr.Close()
			got, err := io.ReadAll(zr)
			if err != nil {
				t.Fatalf("level %d: decompress failed: %v", level, err)
			}
			if string(got) != testStanza {
				t.Fatalf("level %d: round-trip mismatch: got %q want %q", level, got, testStanza)
			}
		})
	}
}

// TestGenerateSuite_XZEnabledDisabled proves XZ is skipped when false and
// produces a valid, round-trippable .xz file when true. XZ has no numeric
// level in publish.Compression (see internal/config's ResolveLive/Snapshot --
// the underlying xz library has no adjustable preset either), so only
// enabled/disabled applies here.
func TestGenerateSuite_XZEnabledDisabled(t *testing.T) {
	files := generate(t, publish.Compression{XZ: false})
	if _, ok := files[relXz]; ok {
		t.Error("XZ: false should not produce a .xz file")
	}

	files = generate(t, publish.Compression{XZ: true})
	data, ok := files[relXz]
	if !ok {
		t.Fatal("XZ: true should produce a .xz file")
	}
	xr, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("not valid xz: %v", err)
	}
	got, err := io.ReadAll(xr)
	if err != nil {
		t.Fatalf("decompress failed: %v", err)
	}
	if string(got) != testStanza {
		t.Fatalf("round-trip mismatch: got %q want %q", got, testStanza)
	}
}

// Package publish generates signed apt repository metadata (Packages, Release,
// InRelease, Release.gpg) and writes it to a file sink.
package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/signing"
)

// FileSink receives generated files at web-root-relative paths.
type FileSink interface {
	WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error
}

// Compression controls which formats are produced and at what level.
// GZip and ZStd use 0 to disable. Positive ZStd levels are mapped via
// zstd.EncoderLevelFromZstd for best-match to the encoder's internal presets.
type Compression struct {
	GZip int  // 0=disabled, 1-9=gzip level
	ZStd int  // 0=disabled, positive mapped via EncoderLevelFromZstd
	XZ   bool // true=enabled (64 MB dict), false=disabled
}

// DefaultSnapshotCompression is the built-in default for snapshot publishing:
// maximum compression for all formats, including xz.
var DefaultSnapshotCompression = Compression{GZip: 9, ZStd: 11, XZ: true}

// DefaultLiveCompression is the built-in default for live publishing:
// fast compression, no xz (apt falls back to gz when xz is absent).
var DefaultLiveCompression = Compression{GZip: 3, ZStd: 3, XZ: false}

// SuiteInput describes one suite (codename) to publish.
type SuiteInput struct {
	OS            string
	Codename      string
	Suite         string
	Origin        string
	Label         string
	Description   string
	Architectures []string
	Components    []string
	// Stanzas[component][arch] holds rendered Packages stanzas.
	Stanzas map[string]map[string][]string
	// SourceStanzas[component] holds rendered Sources stanzas. When non-nil,
	// {component}/source/Sources (and compressed variants) are written for each
	// component that has at least one stanza.
	SourceStanzas map[string][]string
	// Date overrides the Release Date (zero = now).
	Date time.Time
	// Compression controls which index formats are produced and at what level.
	// Zero value disables all formats — callers should set DefaultSnapshotCompression
	// or DefaultLiveCompression, or resolve from config.
	Compression Compression
}

type hashedFile struct {
	rel    string // relative to dists/{codename}
	size   int64
	sha256 string
	sha512 string
}

// sizeWriter counts bytes written through it.
type sizeWriter struct{ n int64 }

func (s *sizeWriter) Write(p []byte) (int, error) {
	s.n += int64(len(p))
	return len(p), nil
}

// GenerateSuite writes the dists/ tree for a suite under prefix (e.g.
// "2026-04-30/debian"), signing Release with key.
func GenerateSuite(ctx context.Context, sink FileSink, prefix string, in SuiteInput, key *signing.Key) error {
	distRoot := path.Join(prefix, "dists", in.Codename)

	var files []hashedFile

	// Build the list of compression variants to produce.
	// xz is ~10× slower than gz/zstd; apt falls back to gz when xz is absent,
	// so it is typically only worth the cost for snapshots.
	type compVariant struct {
		suffix    string
		newWriter func(io.Writer) (io.WriteCloser, error)
	}
	var variants []compVariant
	if in.Compression.XZ {
		variants = append(variants, compVariant{".xz", func(w io.Writer) (io.WriteCloser, error) {
			return xz.WriterConfig{DictCap: 64 << 20}.NewWriter(w)
		}})
	}
	if in.Compression.GZip > 0 {
		level := in.Compression.GZip
		variants = append(variants, compVariant{".gz", func(w io.Writer) (io.WriteCloser, error) {
			return gzip.NewWriterLevel(w, level)
		}})
	}
	if in.Compression.ZStd > 0 {
		level := in.Compression.ZStd
		encoderLevel := zstd.EncoderLevelFromZstd(level)
		variants = append(variants, compVariant{".zst", func(w io.Writer) (io.WriteCloser, error) {
			return zstd.NewWriter(w, zstd.WithEncoderLevel(encoderLevel))
		}})
	}

	// streamStanzas fans stanzas through hashers and all compressors simultaneously
	// via io.MultiWriter so the full plain content is never assembled into one buffer.
	// It returns hashes and size for the plain stream, plus filled compressor buffers.
	streamStanzas := func(stanzas []string, varBufs []bytes.Buffer, varWCs []io.WriteCloser) (h256, h512 []byte, plainSize int64, err error) {
		hasher256 := sha256.New()
		hasher512 := sha512.New()
		var sw sizeWriter

		dests := make([]io.Writer, 0, 3+len(varWCs))
		dests = append(dests, hasher256, hasher512, &sw)
		for i := range varWCs {
			dests = append(dests, varWCs[i])
		}
		mw := io.MultiWriter(dests...)

		var writeErr error
		write := func(s string) {
			if writeErr != nil {
				return
			}
			_, writeErr = io.WriteString(mw, s)
		}
		for i, s := range stanzas {
			if i > 0 {
				write("\n")
			}
			write(s)
		}
		if n := len(stanzas); n > 0 {
			last := stanzas[n-1]
			if len(last) == 0 || last[len(last)-1] != '\n' {
				write("\n")
			}
		}
		if writeErr != nil {
			return nil, nil, 0, writeErr
		}
		for i, wc := range varWCs {
			if cerr := wc.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("close %s: %w", variants[i].suffix, cerr)
			}
		}
		if err != nil {
			return nil, nil, 0, err
		}
		return hasher256.Sum(nil), hasher512.Sum(nil), sw.n, nil
	}

	comps := append([]string(nil), in.Components...)
	sort.Strings(comps)
	arches := append([]string(nil), in.Architectures...)
	sort.Strings(arches)

	type compFile struct {
		suffix string
		data   []byte
		hf     hashedFile
	}
	type jobResult struct {
		plain      hashedFile
		compressed []compFile
		err        error
	}

	// Build the list of (comp, arch) combos to process.
	var combos []struct{ comp, arch, base string }
	for _, comp := range comps {
		for _, arch := range arches {
			combos = append(combos, struct{ comp, arch, base string }{
				comp, arch, fmt.Sprintf("%s/binary-%s", comp, arch),
			})
		}
	}

	// Process combos in GOMAXPROCS-sized batches. Each goroutine streams stanzas
	// through io.MultiWriter into all compressor buffers simultaneously — the plain
	// content is never assembled as one allocation. After a batch completes its
	// results are written to the sink and released before the next batch starts.
	concurrency := runtime.GOMAXPROCS(0)
	for batchStart := 0; batchStart < len(combos); batchStart += concurrency {
		batch := combos[batchStart:min(batchStart+concurrency, len(combos))]

		batchResults := make([]jobResult, len(batch))
		var batchWg sync.WaitGroup
		for j, c := range batch {
			batchWg.Add(1)
			j, c := j, c
			go func() {
				defer batchWg.Done()
				stanzas := in.Stanzas[c.comp][c.arch]

				varBufs := make([]bytes.Buffer, len(variants))
				varWCs := make([]io.WriteCloser, len(variants))
				for i, v := range variants {
					wc, err := v.newWriter(&varBufs[i])
					if err != nil {
						batchResults[j] = jobResult{err: fmt.Errorf("open %s: %w", v.suffix, err)}
						return
					}
					varWCs[i] = wc
				}

				sum256, sum512, plainSize, err := streamStanzas(stanzas, varBufs, varWCs)
				if err != nil {
					batchResults[j] = jobResult{err: err}
					return
				}

				jr := jobResult{
					plain: hashedFile{
						rel:    c.base + "/Packages",
						size:   plainSize,
						sha256: hex.EncodeToString(sum256),
						sha512: hex.EncodeToString(sum512),
					},
					compressed: make([]compFile, len(variants)),
				}
				for i, v := range variants {
					data := varBufs[i].Bytes()
					cs256 := sha256.Sum256(data)
					cs512 := sha512.Sum512(data)
					jr.compressed[i] = compFile{
						suffix: v.suffix,
						data:   data,
						hf: hashedFile{
							rel:    c.base + "/Packages" + v.suffix,
							size:   int64(len(data)),
							sha256: hex.EncodeToString(cs256[:]),
							sha512: hex.EncodeToString(cs512[:]),
						},
					}
				}
				batchResults[j] = jr
			}()
		}
		batchWg.Wait()

		// Write compressed files to the sink; plain bytes were never assembled
		// so there is nothing to write for the plain path (its hash is recorded
		// in Release for clients that need it).
		for _, jr := range batchResults {
			if jr.err != nil {
				return jr.err
			}
			files = append(files, jr.plain)
			for _, cf := range jr.compressed {
				full := path.Join(distRoot, cf.hf.rel)
				if err := sink.WriteFile(ctx, full, bytes.NewReader(cf.data), cf.hf.size); err != nil {
					return err
				}
				files = append(files, cf.hf)
			}
		}
	}

	// Generate source/Sources files for components that have source stanzas.
	for comp, stanzas := range in.SourceStanzas {
		if len(stanzas) == 0 {
			continue
		}
		varBufs := make([]bytes.Buffer, len(variants))
		varWCs := make([]io.WriteCloser, len(variants))
		for i, v := range variants {
			wc, err := v.newWriter(&varBufs[i])
			if err != nil {
				return fmt.Errorf("open %s for sources: %w", v.suffix, err)
			}
			varWCs[i] = wc
		}

		sum256, sum512, plainSize, err := streamStanzas(stanzas, varBufs, varWCs)
		if err != nil {
			return err
		}

		plain := hashedFile{
			rel:    comp + "/source/Sources",
			size:   plainSize,
			sha256: hex.EncodeToString(sum256),
			sha512: hex.EncodeToString(sum512),
		}
		files = append(files, plain)

		for i, v := range variants {
			data := varBufs[i].Bytes()
			cs256 := sha256.Sum256(data)
			cs512 := sha512.Sum512(data)
			hf := hashedFile{
				rel:    comp + "/source/Sources" + v.suffix,
				size:   int64(len(data)),
				sha256: hex.EncodeToString(cs256[:]),
				sha512: hex.EncodeToString(cs512[:]),
			}
			if err := sink.WriteFile(ctx, path.Join(distRoot, hf.rel), bytes.NewReader(data), hf.size); err != nil {
				return err
			}
			files = append(files, hf)
		}
	}

	release := buildRelease(in, files)
	releaseBytes := []byte(release)

	if err := sink.WriteFile(ctx, path.Join(distRoot, "Release"), bytes.NewReader(releaseBytes), int64(len(releaseBytes))); err != nil {
		return err
	}

	if key != nil {
		var (
			inRelease  []byte
			releaseGpg []byte
			signInErr  error
			signDetErr error
		)
		var signWg sync.WaitGroup
		signWg.Add(2)
		go func() { defer signWg.Done(); inRelease, signInErr = key.SignInline(releaseBytes) }()
		go func() { defer signWg.Done(); releaseGpg, signDetErr = key.SignDetached(releaseBytes) }()
		signWg.Wait()
		if signInErr != nil {
			return signInErr
		}
		if signDetErr != nil {
			return signDetErr
		}
		if err := sink.WriteFile(ctx, path.Join(distRoot, "InRelease"), bytes.NewReader(inRelease), int64(len(inRelease))); err != nil {
			return err
		}
		if err := sink.WriteFile(ctx, path.Join(distRoot, "Release.gpg"), bytes.NewReader(releaseGpg), int64(len(releaseGpg))); err != nil {
			return err
		}
	}
	return nil
}

func buildRelease(in SuiteInput, files []hashedFile) string {
	p := apt.NewParagraph()
	if in.Origin != "" {
		p.Set("Origin", in.Origin)
	}
	if in.Label != "" {
		p.Set("Label", in.Label)
	}
	suite := in.Suite
	if suite == "" {
		suite = in.Codename
	}
	p.Set("Suite", suite)
	p.Set("Codename", in.Codename)
	date := in.Date
	if date.IsZero() {
		date = time.Now()
	}
	p.Set("Date", date.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC"))
	p.Set("Architectures", strings.Join(in.Architectures, " "))
	p.Set("Components", strings.Join(in.Components, " "))
	if in.Description != "" {
		p.Set("Description", in.Description)
	}

	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })

	var sb256, sb512 strings.Builder
	for _, f := range files {
		sb256.WriteString(fmt.Sprintf("\n %s %d %s", f.sha256, f.size, f.rel))
		sb512.WriteString(fmt.Sprintf("\n %s %d %s", f.sha512, f.size, f.rel))
	}
	p.Set("SHA256", strings.TrimPrefix(sb256.String(), "\n"))
	p.Set("SHA512", strings.TrimPrefix(sb512.String(), "\n"))

	out, _ := apt.StanzaString(p)
	return out
}



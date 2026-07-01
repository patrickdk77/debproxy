// Package publish generates signed apt repository metadata (Packages, Release,
// InRelease, Release.gpg) and writes it to a file sink.
package publish

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
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
	// HashTypes lists which hash sections to write to Release/InRelease.
	// Valid values: "sha256", "sha512", "sha1", "md5sum". Defaults to ["sha256"].
	HashTypes []string
}

type hashedFile struct {
	rel    string // relative to dists/{codename}
	size   int64
	sha256 string
	sha512 string
	sha1   string
	md5sum string
}

// sizeWriter counts bytes written through it.
type sizeWriter struct{ n int64 }

func (s *sizeWriter) Write(p []byte) (int, error) {
	s.n += int64(len(p))
	return len(p), nil
}

// activeHashTypes returns the effective hash type list, defaulting to sha256.
func activeHashTypes(types []string) []string {
	if len(types) == 0 {
		return []string{"sha256"}
	}
	return types
}

// hashWriters builds one hash.Hash per configured type in the order
// md5sum, sha1, sha256, sha512 and returns them as io.Writers alongside a
// function that reads the final digests into a hashedFile.
func hashWriters(types []string) ([]io.Writer, func(*hashedFile)) {
	var hMD5, hSHA1, hSHA256, hSHA512 hash.Hash
	for _, t := range types {
		switch t {
		case "md5sum":
			hMD5 = md5.New()
		case "sha1":
			hSHA1 = sha1.New()
		case "sha256":
			hSHA256 = sha256.New()
		case "sha512":
			hSHA512 = sha512.New()
		}
	}
	var ws []io.Writer
	if hMD5 != nil {
		ws = append(ws, hMD5)
	}
	if hSHA1 != nil {
		ws = append(ws, hSHA1)
	}
	if hSHA256 != nil {
		ws = append(ws, hSHA256)
	}
	if hSHA512 != nil {
		ws = append(ws, hSHA512)
	}
	populate := func(hf *hashedFile) {
		if hMD5 != nil {
			hf.md5sum = hex.EncodeToString(hMD5.Sum(nil))
		}
		if hSHA1 != nil {
			hf.sha1 = hex.EncodeToString(hSHA1.Sum(nil))
		}
		if hSHA256 != nil {
			hf.sha256 = hex.EncodeToString(hSHA256.Sum(nil))
		}
		if hSHA512 != nil {
			hf.sha512 = hex.EncodeToString(hSHA512.Sum(nil))
		}
	}
	return ws, populate
}

// hashBytes computes all configured hashes of data and returns a hashedFile
// with size and all hash fields populated (rel is left empty for the caller).
func hashBytes(data []byte, types []string) hashedFile {
	ws, populate := hashWriters(types)
	if len(ws) > 0 {
		mw := io.MultiWriter(ws...)
		_, _ = mw.Write(data) // hash.Hash.Write never returns an error
	}
	var hf hashedFile
	hf.size = int64(len(data))
	populate(&hf)
	return hf
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

	hashTypes := activeHashTypes(in.HashTypes)

	// streamStanzas fans stanzas through hashers and all compressors simultaneously
	// via io.MultiWriter so the full plain content is never assembled into one buffer.
	// It returns a hashedFile with size and all configured hashes populated (rel unset).
	streamStanzas := func(stanzas []string, varWCs []io.WriteCloser) (hf hashedFile, err error) {
		hw, populateHashes := hashWriters(hashTypes)
		var sw sizeWriter

		dests := make([]io.Writer, 0, 1+len(hw)+len(varWCs))
		dests = append(dests, &sw)
		dests = append(dests, hw...)
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
			return hashedFile{}, writeErr
		}
		for i, wc := range varWCs {
			if cerr := wc.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("close %s: %w", variants[i].suffix, cerr)
			}
		}
		if err != nil {
			return hashedFile{}, err
		}
		hf.size = sw.n
		populateHashes(&hf)
		return hf, nil
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

				ph, err := streamStanzas(stanzas, varWCs)
				if err != nil {
					batchResults[j] = jobResult{err: err}
					return
				}
				ph.rel = c.base + "/Packages"

				jr := jobResult{
					plain:      ph,
					compressed: make([]compFile, len(variants)),
				}
				for i, v := range variants {
					data := varBufs[i].Bytes()
					cfhf := hashBytes(data, hashTypes)
					cfhf.rel = c.base + "/Packages" + v.suffix
					jr.compressed[i] = compFile{
						suffix: v.suffix,
						data:   data,
						hf:     cfhf,
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

		ph, err := streamStanzas(stanzas, varWCs)
		if err != nil {
			return err
		}
		ph.rel = comp + "/source/Sources"
		files = append(files, ph)

		for i, v := range variants {
			data := varBufs[i].Bytes()
			hf := hashBytes(data, hashTypes)
			hf.rel = comp + "/source/Sources" + v.suffix
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

	// Write hash sections in Debian convention order: MD5Sum, SHA1, SHA256, SHA512.
	type hashSection struct {
		key   string // config value
		field string // Release field name
		get   func(hashedFile) string
	}
	sections := []hashSection{
		{"md5sum", "MD5Sum", func(f hashedFile) string { return f.md5sum }},
		{"sha1", "SHA1", func(f hashedFile) string { return f.sha1 }},
		{"sha256", "SHA256", func(f hashedFile) string { return f.sha256 }},
		{"sha512", "SHA512", func(f hashedFile) string { return f.sha512 }},
	}
	enabled := make(map[string]bool, len(in.HashTypes))
	for _, t := range activeHashTypes(in.HashTypes) {
		enabled[t] = true
	}
	for _, sect := range sections {
		if !enabled[sect.key] {
			continue
		}
		var sb strings.Builder
		for _, f := range files {
			h := sect.get(f)
			if h == "" {
				continue
			}
			sb.WriteString(fmt.Sprintf("\n %s %d %s", h, f.size, f.rel))
		}
		if sb.Len() > 0 {
			p.Set(sect.field, strings.TrimPrefix(sb.String(), "\n"))
		}
	}

	out, _ := apt.StanzaString(p)
	return out
}



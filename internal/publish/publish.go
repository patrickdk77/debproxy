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
	"sort"
	"strconv"
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
	// Date overrides the Release Date (zero = now).
	Date time.Time
	// FastCompression selects speed over ratio (level 1 / fastest presets).
	// Leave false for snapshots, which are written once and served many times.
	FastCompression bool
}

type hashedFile struct {
	rel    string // relative to dists/{codename}
	size   int64
	sha256 string
	sha512 string
}

// GenerateSuite writes the dists/ tree for a suite under prefix (e.g.
// "2026-04-30/debian"), signing Release with key.
func GenerateSuite(ctx context.Context, sink FileSink, prefix string, in SuiteInput, key *signing.Key) error {
	distRoot := path.Join(prefix, "dists", in.Codename)

	var files []hashedFile

	// Compression variants. xz is skipped for the live path (FastCompression)
	// because it is ~10× slower than gz/zstd and apt falls back to gz when xz
	// is absent from InRelease. Snapshots keep xz for maximum compression.
	type compVariant struct {
		suffix string
		fn     func([]byte) ([]byte, error)
	}
	var variants []compVariant
	if !in.FastCompression {
		variants = append(variants, compVariant{".xz", func(d []byte) ([]byte, error) { return xzBytes(d, false) }})
	}
	variants = append(variants,
		compVariant{".gz", func(d []byte) ([]byte, error) { return gzipBytes(d, in.FastCompression) }},
		compVariant{".zst", func(d []byte) ([]byte, error) { return zstdBytes(d, in.FastCompression) }},
	)

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
		base       string
		content    []byte
		plain      hashedFile
		compressed []compFile
		err        error
	}

	// For each (comp,arch) combo: build content, hash it, compress it, and hash
	// the compressed output — all in one goroutine per combo so CPU-intensive
	// work (Join, SHA256/512, compress) runs across all cores simultaneously.
	var combos []struct{ comp, arch, base string }
	for _, comp := range comps {
		for _, arch := range arches {
			combos = append(combos, struct{ comp, arch, base string }{
				comp, arch, fmt.Sprintf("%s/binary-%s", comp, arch),
			})
		}
	}

	jobResults := make([]jobResult, len(combos))
	var wg sync.WaitGroup
	for i, c := range combos {
		wg.Add(1)
		i, c := i, c
		go func() {
			defer wg.Done()
			stanzas := in.Stanzas[c.comp][c.arch]
			content := []byte(strings.Join(stanzas, "\n"))
			if len(content) > 0 && content[len(content)-1] != '\n' {
				content = append(content, '\n')
			}
			sum256 := sha256.Sum256(content)
			sum512 := sha512.Sum512(content)
			jr := jobResult{
				base:    c.base,
				content: content,
				plain: hashedFile{
					rel:    c.base + "/Packages",
					size:   int64(len(content)),
					sha256: hex.EncodeToString(sum256[:]),
					sha512: hex.EncodeToString(sum512[:]),
				},
				compressed: make([]compFile, len(variants)),
			}
			// Run each compression variant in its own goroutine so gz and zst
			// compress concurrently (universe/amd64 gz alone takes ~2s).
			var compWg sync.WaitGroup
			var compErrOnce sync.Once
			for vi, v := range variants {
				compWg.Add(1)
				vi, v := vi, v
				go func() {
					defer compWg.Done()
					data, err := v.fn(content)
					if err != nil {
						compErrOnce.Do(func() { jr.err = err })
						return
					}
					cs256 := sha256.Sum256(data)
					cs512 := sha512.Sum512(data)
					jr.compressed[vi] = compFile{
						suffix: v.suffix,
						data:   data,
						hf: hashedFile{
							rel:    c.base + "/Packages" + v.suffix,
							size:   int64(len(data)),
							sha256: hex.EncodeToString(cs256[:]),
							sha512: hex.EncodeToString(cs512[:]),
						},
					}
				}()
			}
			compWg.Wait()
			jobResults[i] = jr
		}()
	}
	wg.Wait()

	// Collect results and write files sequentially (order determines Release
	// field output, though buildRelease re-sorts by rel path anyway).
	for _, jr := range jobResults {
		if jr.err != nil {
			return jr.err
		}
		full := path.Join(distRoot, jr.plain.rel)
		if err := sink.WriteFile(ctx, full, bytes.NewReader(jr.content), jr.plain.size); err != nil {
			return err
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
		sb256.WriteString(fmt.Sprintf("\n %s %s %s", f.sha256, padSize(f.size), f.rel))
		sb512.WriteString(fmt.Sprintf("\n %s %s %s", f.sha512, padSize(f.size), f.rel))
	}
	p.Set("SHA256", strings.TrimPrefix(sb256.String(), "\n"))
	p.Set("SHA512", strings.TrimPrefix(sb512.String(), "\n"))

	out, _ := apt.StanzaString(p)
	return out
}

func padSize(n int64) string {
	return strconv.FormatInt(n, 10)
}

func xzBytes(data []byte, fast bool) ([]byte, error) {
	dictCap := 64 << 20 // 64 MB — xz preset 9
	if fast {
		dictCap = 2 << 20 // 2 MB — xz preset 2
	}
	var buf bytes.Buffer
	xw, err := xz.WriterConfig{DictCap: dictCap}.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := xw.Write(data); err != nil {
		return nil, err
	}
	if err := xw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gzipBytes(data []byte, fast bool) ([]byte, error) {
	level := gzip.BestCompression // 9
	if fast {
		level = 3
	}
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := gw.Write(data); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zstdBytes(data []byte, fast bool) ([]byte, error) {
	level := zstd.SpeedBestCompression
	if fast {
		level = zstd.SpeedDefault // level 3
	}
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(level))
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

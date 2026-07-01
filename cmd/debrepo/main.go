// debrepo generates signed apt repository metadata (Packages, Release,
// InRelease) from .deb files stored on disk. It requires no config file;
// all parameters are supplied via flags. State is persisted per component
// as a zstd-compressed deb822 file so subsequent runs only process changes.
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/deb"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/signing"
)

// diskEntry holds on-disk metadata used for change detection.
type diskEntry struct {
	size  int64
	mtime string
}

func main() {
	keyPath := flag.String("key", "", "path to OpenPGP signing key (required)")
	dir := flag.String("dir", "", "path to repository root (required)")
	osName := flag.String("os", "", "OS name, e.g. ubuntu (required)")
	origin := flag.String("origin", "", "Release Origin (default: value of -os)")
	label := flag.String("label", "", "Release Label (default: value of -os)")
	force := flag.Bool("force", false, "discard saved state and reprocess all packages from scratch")
	flag.Parse()

	if *keyPath == "" || *dir == "" || *osName == "" {
		fmt.Fprintln(os.Stderr, "usage: debrepo -key <path> -dir <repo-root> -os <name> [-origin <s>] [-label <s>] [-force]")
		os.Exit(1)
	}
	if *origin == "" {
		*origin = *osName
	}
	if *label == "" {
		*label = *osName
	}

	signingKey, err := signing.Load(*keyPath)
	if err != nil {
		slog.Error("load signing key", "err", err)
		os.Exit(1)
	}

	if err := run(context.Background(), *dir, *osName, *origin, *label, *force, signingKey); err != nil {
		slog.Error("failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dir, osName, origin, label string, force bool, key *signing.Key) error {
	sink := fsSink{base: dir}
	distsDir := filepath.Join(dir, "dists")

	poolParas, err := scanPool(filepath.Join(dir, "pool"), force)
	if err != nil {
		slog.Warn("pool scan failed", "err", err)
	}

	codenames, err := subdirs(distsDir)
	if err != nil {
		return fmt.Errorf("scan dists dir %s: %w", distsDir, err)
	}

	for _, codename := range codenames {
		if err := processCodename(ctx, sink, filepath.Join(distsDir, codename), codename, poolParas, osName, origin, label, force, key); err != nil {
			slog.Error("codename failed", "codename", codename, "err", err)
		}
	}
	return nil
}

func processCodename(ctx context.Context, sink fsSink, codenamePath, codename string, poolParas map[string][]*apt.Paragraph, osName, origin, label string, force bool, key *signing.Key) error {
	slog.Info("processing codename", "codename", codename)

	comps, err := subdirs(codenamePath)
	if err != nil {
		return fmt.Errorf("scan codename dir: %w", err)
	}

	// Phase 1: per component  -- discover arches, reconcile state with disk, add new debs/dscs.
	type compData struct {
		paras    []*apt.Paragraph
		srcParas []*apt.Paragraph
	}
	archSet := map[string]bool{}
	compMap := make(map[string]compData, len(comps))

	for _, comp := range comps {
		compPath := filepath.Join(codenamePath, comp)

		for _, a := range discoverArches(compPath) {
			archSet[a] = true
		}

		var paras []*apt.Paragraph
		if !force {
			var err error
			paras, err = loadState(compPath, ".debrepo")
			if err != nil {
				slog.Warn("load state failed, starting fresh", "component", comp, "err", err)
			}
		}

		// Enumerate .deb files recursively under deb/.
		debDir := filepath.Join(compPath, "deb")
		debPrefix := "dists/" + codename + "/" + comp + "/deb/"
		diskFiles := make(map[string]diskEntry)
		_ = filepath.Walk(debDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".deb") {
				return nil
			}
			rel, _ := filepath.Rel(debDir, p)
			diskFiles[debPrefix+filepath.ToSlash(rel)] = diskEntry{
				size:  info.Size(),
				mtime: info.ModTime().UTC().Format(time.RFC3339),
			}
			return nil
		})

		// Remove state entries for deleted or modified .deb files.
		filtered := paras[:0:0]
		removedCount, modifiedCount := 0, 0
		for _, p := range paras {
			de, onDisk := diskFiles[p.Get("Filename")]
			if !onDisk {
				slog.Info("removing deleted package", "component", comp, "file", p.Get("Filename"))
				removedCount++
				continue
			}
			if de.mtime != p.Get("X-Mtime") || strconv.FormatInt(de.size, 10) != p.Get("Size") {
				slog.Info("reprocessing modified package", "component", comp, "file", p.Get("Filename"))
				modifiedCount++
				continue
			}
			filtered = append(filtered, p)
		}
		paras = filtered

		// Build seen set from unchanged state entries.
		seen := make(map[string]bool, len(paras))
		for _, p := range paras {
			seen[p.Get("Filename")] = true
		}

		// Process new and modified .deb files (sorted for deterministic output).
		toProcess := make([]string, 0, len(diskFiles))
		for k := range diskFiles {
			if !seen[k] {
				toProcess = append(toProcess, k)
			}
		}
		sort.Strings(toProcess)

		newCount := 0
		for _, filenameKey := range toProcess {
			relPath := strings.TrimPrefix(filenameKey, debPrefix)
			debFile := filepath.Join(debDir, filepath.FromSlash(relPath))
			para, err := processDeb(debFile, debPrefix, relPath)
			if err != nil {
				slog.Warn("skip deb", "file", debFile, "err", err)
				continue
			}
			para.Set("X-Mtime", diskFiles[filenameKey].mtime)
			if arch := para.Get("Architecture"); arch != "all" {
				archSet[arch] = true
			}
			paras = append(paras, para)
			newCount++
		}

		if newCount > 0 || removedCount > 0 || modifiedCount > 0 || force {
			slog.Info("state updated", "component", comp, "added", newCount, "removed", removedCount, "modified", modifiedCount)
			if err := saveState(compPath, ".debrepo", paras); err != nil {
				slog.Warn("save state failed", "component", comp, "err", err)
			}
		}

		// Source packages: scan <component>/source/ for .dsc files.
		// Skip entirely if the source directory does not exist.
		srcDir := filepath.Join(compPath, "source")
		srcPrefix := "dists/" + codename + "/" + comp + "/source/"
		srcDiskFiles := make(map[string]diskEntry)
		if _, err := os.Stat(srcDir); err == nil {
			_ = filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
				if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".dsc") {
					return nil
				}
				rel, _ := filepath.Rel(srcDir, p)
				srcDiskFiles[srcPrefix+filepath.ToSlash(rel)] = diskEntry{
					size:  info.Size(),
					mtime: info.ModTime().UTC().Format(time.RFC3339),
				}
				return nil
			})
		}

		var srcParas []*apt.Paragraph
		if !force && len(srcDiskFiles) > 0 {
			var err error
			srcParas, err = loadState(compPath, ".debrepo-src")
			if err != nil {
				slog.Warn("load source state failed, starting fresh", "component", comp, "err", err)
			}
		}

		// Remove state entries for deleted or modified .dsc files.
		srcFiltered := srcParas[:0:0]
		srcRemovedCount, srcModifiedCount := 0, 0
		for _, p := range srcParas {
			dscKey := p.Get("X-DscPath")
			de, onDisk := srcDiskFiles[dscKey]
			if !onDisk {
				slog.Info("removing deleted source package", "component", comp, "file", dscKey)
				srcRemovedCount++
				continue
			}
			if de.mtime != p.Get("X-Mtime") || strconv.FormatInt(de.size, 10) != p.Get("X-DscSize") {
				slog.Info("reprocessing modified source package", "component", comp, "file", dscKey)
				srcModifiedCount++
				continue
			}
			srcFiltered = append(srcFiltered, p)
		}
		srcParas = srcFiltered

		srcSeen := make(map[string]bool, len(srcParas))
		for _, p := range srcParas {
			srcSeen[p.Get("X-DscPath")] = true
		}

		srcToProcess := make([]string, 0, len(srcDiskFiles))
		for k := range srcDiskFiles {
			if !srcSeen[k] {
				srcToProcess = append(srcToProcess, k)
			}
		}
		sort.Strings(srcToProcess)

		srcNewCount := 0
		for _, dscKey := range srcToProcess {
			relPath := strings.TrimPrefix(dscKey, srcPrefix)
			dscFile := filepath.Join(srcDir, filepath.FromSlash(relPath))
			para, err := processDsc(dscFile, codename, comp, relPath)
			if err != nil {
				slog.Warn("skip dsc", "file", dscFile, "err", err)
				continue
			}
			de := srcDiskFiles[dscKey]
			para.Set("X-DscPath", dscKey)
			para.Set("X-Mtime", de.mtime)
			para.Set("X-DscSize", strconv.FormatInt(de.size, 10))
			srcParas = append(srcParas, para)
			srcNewCount++
		}

		if srcNewCount > 0 || srcRemovedCount > 0 || srcModifiedCount > 0 || (force && len(srcDiskFiles) > 0) {
			slog.Info("source state updated", "component", comp, "added", srcNewCount, "removed", srcRemovedCount, "modified", srcModifiedCount)
			if err := saveState(compPath, ".debrepo-src", srcParas); err != nil {
				slog.Warn("save source state failed", "component", comp, "err", err)
			}
		}

		// Collect architectures from pool packages for this component.
		for _, p := range poolParas[comp] {
			if arch := p.Get("Architecture"); arch != "" && arch != "all" {
				archSet[arch] = true
			}
		}

		compMap[comp] = compData{paras, srcParas}
	}

	// Phase 2: fan packages into per-(component, arch) stanza slices.
	// arch=all packages are fanned into every arch in the global archSet.
	suiteStanzas := make(map[string]map[string][]string, len(comps))
	sourceStanzas := make(map[string][]string, len(comps))
	for _, comp := range comps {
		suiteStanzas[comp] = map[string][]string{}
		for _, p := range compMap[comp].paras {
			arch := p.Get("Architecture")
			stanzaStr, err := renderStanza(p)
			if err != nil {
				slog.Warn("render stanza", "err", err)
				continue
			}
			if arch == "all" {
				for a := range archSet {
					suiteStanzas[comp][a] = append(suiteStanzas[comp][a], stanzaStr)
				}
			} else {
				suiteStanzas[comp][arch] = append(suiteStanzas[comp][arch], stanzaStr)
			}
		}
		for _, p := range poolParas[comp] {
			arch := p.Get("Architecture")
			stanzaStr, err := renderStanza(p)
			if err != nil {
				slog.Warn("render pool stanza", "err", err)
				continue
			}
			if arch == "all" {
				for a := range archSet {
					suiteStanzas[comp][a] = append(suiteStanzas[comp][a], stanzaStr)
				}
			} else {
				suiteStanzas[comp][arch] = append(suiteStanzas[comp][arch], stanzaStr)
			}
		}
		for _, p := range compMap[comp].srcParas {
			s, err := renderStanza(p)
			if err != nil {
				slog.Warn("render source stanza", "err", err)
				continue
			}
			sourceStanzas[comp] = append(sourceStanzas[comp], s)
		}
	}

	sortedComps := append([]string(nil), comps...)
	sort.Strings(sortedComps)

	expand := func(s string) string {
		return strings.ReplaceAll(s, "{codename}", codename)
	}

	return publish.GenerateSuite(ctx, sink, "", publish.SuiteInput{
		OS:            expand(osName),
		Codename:      codename,
		Suite:         codename,
		Origin:        expand(origin),
		Label:         expand(label),
		Architectures: sortedKeys(archSet),
		Components:    sortedComps,
		Stanzas:       suiteStanzas,
		SourceStanzas: sourceStanzas,
		Compression:   publish.DefaultSnapshotCompression,
		HashTypes:     []string{"md5sum", "sha1", "sha256", "sha512"},
	}, key)
}

func processDeb(debFile, filenamePrefix, relPath string) (*apt.Paragraph, error) {
	f, err := os.Open(debFile)
	if err != nil {
		return nil, err
	}
	ctrl, err := deb.ControlParagraph(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("control paragraph: %w", err)
	}

	sha256hex, sha512hex, size, err := computeChecksums(debFile)
	if err != nil {
		return nil, fmt.Errorf("checksums: %w", err)
	}

	return apt.BuildPackagesStanza(ctrl, filenamePrefix+relPath, size, sha256hex, sha512hex), nil
}

func computeChecksums(path string) (sha256hex, sha512hex string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()

	h256 := sha256.New()
	h512 := sha512.New()
	n, err := io.Copy(io.MultiWriter(h256, h512), f)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h512.Sum(nil)), n, nil
}

// loadState reads the per-component state file named <name>.zst, falling back
// to <name>.old.zst on error.
func loadState(compPath, name string) ([]*apt.Paragraph, error) {
	stateFile := filepath.Join(compPath, name+".zst")
	oldFile := filepath.Join(compPath, name+".old.zst")

	paras, err := readStateFile(stateFile)
	if err == nil {
		return paras, nil
	}
	paras, err2 := readStateFile(oldFile)
	if err2 == nil {
		slog.Warn("using fallback state", "path", oldFile)
		return paras, nil
	}
	return nil, err
}

func readStateFile(path string) ([]*apt.Paragraph, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return apt.ParseParagraphs(zr)
}

// saveState atomically writes the component state to <name>.zst, preserving
// the previous file as <name>.old.zst.
func saveState(compPath, name string, paras []*apt.Paragraph) error {
	stateFile := filepath.Join(compPath, name+".zst")
	oldFile := filepath.Join(compPath, name+".old.zst")

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		return err
	}
	if err := apt.WriteParagraphs(zw, paras); err != nil {
		zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	if _, err := os.Stat(stateFile); err == nil {
		_ = os.Rename(stateFile, oldFile)
	}

	tmp := stateFile + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, stateFile)
}

// discoverArches returns architectures from binary-{arch} subdirectories.
func discoverArches(compPath string) []string {
	entries, err := os.ReadDir(compPath)
	if err != nil {
		return nil
	}
	var arches []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if arch, ok := strings.CutPrefix(e.Name(), "binary-"); ok && arch != "" {
			arches = append(arches, arch)
		}
	}
	return arches
}

// subdirs returns names of immediate subdirectories within dir.
func subdirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderStanza renders p as a deb822 string, omitting X-* private state fields.
func renderStanza(p *apt.Paragraph) (string, error) {
	clean := apt.NewParagraph()
	for _, k := range p.Keys() {
		if !strings.HasPrefix(strings.ToLower(k), "x-") {
			clean.Set(k, p.Get(k))
		}
	}
	return apt.StanzaString(clean)
}

// processDsc builds a Sources stanza paragraph from a .dsc file.
func processDsc(dscFile, codename, comp, relPath string) (*apt.Paragraph, error) {
	data, err := os.ReadFile(dscFile)
	if err != nil {
		return nil, err
	}

	paras, err := apt.ParseParagraphs(bytes.NewReader(stripPGPArmor(data)))
	if err != nil || len(paras) == 0 {
		if err == nil {
			err = fmt.Errorf("no paragraphs found")
		}
		return nil, fmt.Errorf("parse dsc: %w", err)
	}
	ctrl := paras[0]

	sourceName := ctrl.Get("Source")
	if sourceName == "" {
		return nil, fmt.Errorf("no Source field in %s", dscFile)
	}

	dscMD5, dscSHA1, dscSHA256, dscSize, err := computeDscChecksums(dscFile)
	if err != nil {
		return nil, fmt.Errorf("checksums: %w", err)
	}

	// Directory: path relative to webroot where all source files live.
	dscSubdir := filepath.ToSlash(filepath.Dir(relPath))
	directory := "dists/" + codename + "/" + comp + "/source"
	if dscSubdir != "" && dscSubdir != "." {
		directory += "/" + dscSubdir
	}

	basename := filepath.Base(dscFile)
	sizeStr := strconv.FormatInt(dscSize, 10)

	out := apt.NewParagraph()
	out.Set("Package", sourceName)
	for _, k := range ctrl.Keys() {
		if !strings.EqualFold(k, "Source") {
			out.Set(k, ctrl.Get(k))
		}
	}
	out.Set("Directory", directory)

	// Append the .dsc file itself to Files (md5), Checksums-Sha1, and Checksums-Sha256.
	for _, field := range []struct{ name, hash string }{
		{"Files", dscMD5},
		{"Checksums-Sha1", dscSHA1},
		{"Checksums-Sha256", dscSHA256},
	} {
		entry := field.hash + " " + sizeStr + " " + basename
		existing := out.Get(field.name)
		if existing == "" {
			out.Set(field.name, "\n"+entry)
		} else {
			out.Set(field.name, existing+"\n"+entry)
		}
	}

	return out, nil
}

func computeDscChecksums(path string) (md5hex, sha1hex, sha256hex string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", 0, err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	h256 := sha256.New()
	n, err := io.Copy(io.MultiWriter(hMD5, hSHA1, h256), f)
	if err != nil {
		return "", "", "", 0, err
	}
	return hex.EncodeToString(hMD5.Sum(nil)), hex.EncodeToString(hSHA1.Sum(nil)), hex.EncodeToString(h256.Sum(nil)), n, nil
}

// stripPGPArmor strips OpenPGP clear-sign armor from a .dsc file if present,
// returning just the deb822 content.
func stripPGPArmor(data []byte) []byte {
	if !bytes.HasPrefix(data, []byte("-----BEGIN PGP")) {
		return data
	}
	s := string(data)
	// Content follows the blank line that terminates the armor headers.
	idx := strings.Index(s, "\n\n")
	if idx < 0 {
		return data
	}
	content := s[idx+2:]
	// Trim the detached signature that follows.
	if end := strings.Index(content, "\n-----BEGIN PGP SIGNATURE-----"); end >= 0 {
		content = content[:end]
	}
	return []byte(content)
}

// scanPool scans pool/<component>/ for .deb files and returns a map of
// component name to Packages paragraphs. The pool directory is shared across
// all codenames; its state is stored per component in pool/<component>/.debrepo.zst.
func scanPool(poolDir string, force bool) (map[string][]*apt.Paragraph, error) {
	if _, err := os.Stat(poolDir); os.IsNotExist(err) {
		return nil, nil
	}
	comps, err := subdirs(poolDir)
	if err != nil {
		return nil, fmt.Errorf("scan pool: %w", err)
	}

	result := make(map[string][]*apt.Paragraph, len(comps))

	for _, comp := range comps {
		compDir := filepath.Join(poolDir, comp)
		prefix := "pool/" + comp + "/"

		diskFiles := make(map[string]diskEntry)
		_ = filepath.Walk(compDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".deb") {
				return nil
			}
			rel, _ := filepath.Rel(compDir, p)
			diskFiles[prefix+filepath.ToSlash(rel)] = diskEntry{
				size:  info.Size(),
				mtime: info.ModTime().UTC().Format(time.RFC3339),
			}
			return nil
		})

		var paras []*apt.Paragraph
		if !force {
			var err error
			paras, err = loadState(compDir, ".debrepo")
			if err != nil {
				slog.Warn("load pool state failed, starting fresh", "component", comp, "err", err)
			}
		}

		filtered := paras[:0:0]
		removedCount, modifiedCount := 0, 0
		for _, p := range paras {
			de, onDisk := diskFiles[p.Get("Filename")]
			if !onDisk {
				slog.Info("removing deleted pool package", "component", comp, "file", p.Get("Filename"))
				removedCount++
				continue
			}
			if de.mtime != p.Get("X-Mtime") || strconv.FormatInt(de.size, 10) != p.Get("Size") {
				slog.Info("reprocessing modified pool package", "component", comp, "file", p.Get("Filename"))
				modifiedCount++
				continue
			}
			filtered = append(filtered, p)
		}
		paras = filtered

		seen := make(map[string]bool, len(paras))
		for _, p := range paras {
			seen[p.Get("Filename")] = true
		}

		toProcess := make([]string, 0, len(diskFiles))
		for k := range diskFiles {
			if !seen[k] {
				toProcess = append(toProcess, k)
			}
		}
		sort.Strings(toProcess)

		newCount := 0
		for _, filenameKey := range toProcess {
			relPath := strings.TrimPrefix(filenameKey, prefix)
			debFile := filepath.Join(compDir, filepath.FromSlash(relPath))
			para, err := processDeb(debFile, prefix, relPath)
			if err != nil {
				slog.Warn("skip pool deb", "file", debFile, "err", err)
				continue
			}
			para.Set("X-Mtime", diskFiles[filenameKey].mtime)
			paras = append(paras, para)
			newCount++
		}

		if newCount > 0 || removedCount > 0 || modifiedCount > 0 || force {
			slog.Info("pool state updated", "component", comp, "added", newCount, "removed", removedCount, "modified", modifiedCount)
			if err := saveState(compDir, ".debrepo", paras); err != nil {
				slog.Warn("save pool state failed", "component", comp, "err", err)
			}
		}

		if len(paras) > 0 {
			result[comp] = paras
		}
	}

	return result, nil
}

// fsSink implements publish.FileSink by writing to the local filesystem.
type fsSink struct{ base string }

func (s fsSink) WriteFile(_ context.Context, relPath string, r io.Reader, _ int64) error {
	full := filepath.Join(s.base, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, full)
}

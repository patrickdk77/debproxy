// debrepo generates signed apt repository metadata (Packages, Release,
// InRelease) from .deb files stored on disk or in an S3 bucket. It requires
// no config file; all parameters are supplied via flags. State is persisted
// per component as a zstd-compressed deb822 file so subsequent runs only
// process changes.
package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
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

// diskEntry holds the stored file's metadata used for change detection.
type diskEntry struct {
	size  int64
	mtime string
}

func newDiskEntry(size int64, mtime time.Time) diskEntry {
	return diskEntry{size: size, mtime: mtime.UTC().Format(time.RFC3339)}
}

func main() {
	keyPath := flag.String("key", "", "path to OpenPGP signing key (required)")
	dir := flag.String("dir", "", "repository root: a directory or s3://[key:secret@]bucket/prefix (required)")
	osName := flag.String("os", "", "OS name, e.g. ubuntu (required)")
	origin := flag.String("origin", "", "Release Origin (default: value of -os)")
	label := flag.String("label", "", "Release Label (default: value of -os)")
	force := flag.Bool("force", false, "discard saved state and reprocess all packages from scratch")
	s3Region := flag.String("s3-region", "", "region of an s3:// repository (default: AWS_REGION)")
	s3Endpoint := flag.String("s3-endpoint", "", "endpoint URL of an s3:// repository, for S3-compatible stores")
	s3PathStyle := flag.Bool("s3-path-style", false, "use path-style addressing for an s3:// repository")
	s3NoACL := flag.Bool("s3-no-acl", false, "set no object ACL on an s3:// repository (buckets with ACLs disabled or public ACLs blocked)")
	flag.Parse()

	if *keyPath == "" || *dir == "" || *osName == "" {
		fmt.Fprintln(os.Stderr, "usage: debrepo -key <path> -dir <repo-root> -os <name> [-origin <s>] [-label <s>] [-force] [-s3-region <r>] [-s3-endpoint <url>] [-s3-path-style] [-s3-no-acl]")
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

	ctx := context.Background()
	repo, err := openRepo(ctx, *dir, s3Flags{region: *s3Region, endpoint: *s3Endpoint, pathStyle: *s3PathStyle, noACL: *s3NoACL})
	if err != nil {
		slog.Error("open repository", "err", err)
		os.Exit(1)
	}
	if err := run(ctx, repo, *osName, *origin, *label, *force, signingKey); err != nil {
		slog.Error("failed", "err", err)
		os.Exit(1)
	}
}

// errUnreadable marks a file the repository listed but could not deliver.
// Such a file must not be dropped from the index as if it were deleted:
// a read denial on a bucket would otherwise publish a signed index
// without its packages.
var errUnreadable = errors.New("listed file could not be read")

func run(ctx context.Context, repo repoFS, osName, origin, label string, force bool, key *signing.Key) error {
	poolParas, err := scanPool(ctx, repo, force)
	if err != nil {
		return fmt.Errorf("scan pool: %w", err)
	}

	codenames, err := repo.subdirs(ctx, "dists")
	if err != nil {
		return fmt.Errorf("scan dists: %w", err)
	}

	failed := 0
	for _, codename := range codenames {
		if err := processCodename(ctx, repo, "dists/"+codename, codename, poolParas, osName, origin, label, force, key); err != nil {
			slog.Error("codename failed", "codename", codename, "err", err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d codenames failed", failed, len(codenames))
	}
	return nil
}

func processCodename(ctx context.Context, repo repoFS, codenamePath, codename string, poolParas map[string][]*apt.Paragraph, osName, origin, label string, force bool, key *signing.Key) error {
	slog.Info("processing codename", "codename", codename)

	comps, err := repo.subdirs(ctx, codenamePath)
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
		compPath := codenamePath + "/" + comp

		for _, a := range discoverArches(ctx, repo, compPath) {
			archSet[a] = true
		}

		var paras []*apt.Paragraph
		if !force {
			var err error
			paras, err = loadState(ctx, repo, compPath, ".debrepo")
			if err != nil {
				slog.Warn("load state failed, starting fresh", "component", comp, "err", err)
			}
		}

		// Enumerate .deb files recursively under deb/.
		debDir := compPath + "/deb"
		debPrefix := debDir + "/"
		diskFiles := make(map[string]diskEntry)
		if err := repo.walk(ctx, debDir, ".deb", func(rel string, size int64, mtime time.Time) {
			diskFiles[debPrefix+rel] = newDiskEntry(size, mtime)
		}); err != nil {
			return fmt.Errorf("walk %s: %w", debDir, err)
		}

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
			para, err := processDeb(ctx, repo, filenameKey)
			if errors.Is(err, errUnreadable) {
				return fmt.Errorf("component %s: %w", comp, err)
			}
			if err != nil {
				slog.Warn("skip deb", "file", filenameKey, "err", err)
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
			if err := saveState(ctx, repo, compPath, ".debrepo", paras); err != nil {
				slog.Warn("save state failed", "component", comp, "err", err)
			}
		}

		// Source packages: scan <component>/source/ for .dsc files. A
		// component without a source directory yields none.
		srcDir := compPath + "/source"
		srcPrefix := srcDir + "/"
		srcDiskFiles := make(map[string]diskEntry)
		if err := repo.walk(ctx, srcDir, ".dsc", func(rel string, size int64, mtime time.Time) {
			srcDiskFiles[srcPrefix+rel] = newDiskEntry(size, mtime)
		}); err != nil {
			return fmt.Errorf("walk %s: %w", srcDir, err)
		}

		var srcParas []*apt.Paragraph
		if !force && len(srcDiskFiles) > 0 {
			var err error
			srcParas, err = loadState(ctx, repo, compPath, ".debrepo-src")
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
			para, err := processDsc(ctx, repo, dscKey, codename, comp, relPath)
			if errors.Is(err, errUnreadable) {
				return fmt.Errorf("component %s: %w", comp, err)
			}
			if err != nil {
				slog.Warn("skip dsc", "file", dscKey, "err", err)
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
			if err := saveState(ctx, repo, compPath, ".debrepo-src", srcParas); err != nil {
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

	return publish.GenerateSuite(ctx, repo, "", publish.SuiteInput{
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

// processDeb builds the Packages stanza for the .deb at filename, which is
// also the stanza's Filename field. The file is read once for its control
// paragraph and once more for its checksums. A file that cannot be read
// is reported with errUnreadable; a file that is not a .deb is an
// ordinary error.
func processDeb(ctx context.Context, repo repoFS, filename string) (*apt.Paragraph, error) {
	f, err := repo.openSeekable(ctx, filename)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUnreadable, filename, err)
	}
	defer f.Close()
	ctrl, err := deb.ControlParagraph(f)
	if err != nil {
		return nil, fmt.Errorf("control paragraph: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUnreadable, filename, err)
	}

	h256 := sha256.New()
	h512 := sha512.New()
	size, err := io.Copy(io.MultiWriter(h256, h512), f)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: checksums: %w", errUnreadable, filename, err)
	}
	return apt.BuildPackagesStanza(ctrl, filename, size, hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h512.Sum(nil))), nil
}

// loadState reads the per-component state file named <name>.zst, falling back
// to <name>.old.zst on error.
func loadState(ctx context.Context, repo repoFS, compPath, name string) ([]*apt.Paragraph, error) {
	stateFile := compPath + "/" + name + ".zst"
	oldFile := compPath + "/" + name + ".old.zst"

	paras, err := readStateFile(ctx, repo, stateFile)
	if err == nil {
		return paras, nil
	}
	paras, err2 := readStateFile(ctx, repo, oldFile)
	if err2 == nil {
		slog.Warn("using fallback state", "path", oldFile)
		return paras, nil
	}
	return nil, err
}

func readStateFile(ctx context.Context, repo repoFS, rel string) ([]*apt.Paragraph, error) {
	f, err := repo.open(ctx, rel)
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

// saveState writes the component state to <name>.zst, keeping the previous
// file as <name>.old.zst.
func saveState(ctx context.Context, repo repoFS, compPath, name string, paras []*apt.Paragraph) error {
	stateFile := compPath + "/" + name + ".zst"
	oldFile := compPath + "/" + name + ".old.zst"

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

	if err := repo.rotate(ctx, stateFile, oldFile); err != nil {
		slog.Warn("keeping the previous state failed", "path", oldFile, "err", err)
	}
	return repo.WriteFile(ctx, stateFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()))
}

// discoverArches returns architectures from binary-{arch} subdirectories.
func discoverArches(ctx context.Context, repo repoFS, compPath string) []string {
	names, err := repo.subdirs(ctx, compPath)
	if err != nil {
		return nil
	}
	var arches []string
	for _, name := range names {
		if arch, ok := strings.CutPrefix(name, "binary-"); ok && arch != "" {
			arches = append(arches, arch)
		}
	}
	return arches
}

// warnWalkErr logs a filepath.Walk error and reports whether the callback
// should skip this entry (true) rather than continue processing it.
func warnWalkErr(kind, p string, err error) bool {
	if err == nil {
		return false
	}
	slog.Warn("walk "+kind+": skipping entry", "path", p, "err", err)
	return true
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

// processDsc builds a Sources stanza paragraph from the .dsc file at dscPath,
// whose path relative to the component's source directory is relPath.
func processDsc(ctx context.Context, repo repoFS, dscPath, codename, comp, relPath string) (*apt.Paragraph, error) {
	rc, err := repo.open(ctx, dscPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUnreadable, dscPath, err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUnreadable, dscPath, err)
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
		return nil, fmt.Errorf("no Source field in %s", dscPath)
	}

	dscMD5, dscSHA1, dscSHA256 := dscChecksums(data)

	// Directory: path relative to webroot where all source files live.
	dscSubdir := path.Dir(relPath)
	directory := "dists/" + codename + "/" + comp + "/source"
	if dscSubdir != "" && dscSubdir != "." {
		directory += "/" + dscSubdir
	}

	basename := path.Base(dscPath)
	sizeStr := strconv.Itoa(len(data))

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

func dscChecksums(data []byte) (md5hex, sha1hex, sha256hex string) {
	sumMD5 := md5.Sum(data)
	sumSHA1 := sha1.Sum(data)
	sum256 := sha256.Sum256(data)
	return hex.EncodeToString(sumMD5[:]), hex.EncodeToString(sumSHA1[:]), hex.EncodeToString(sum256[:])
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
func scanPool(ctx context.Context, repo repoFS, force bool) (map[string][]*apt.Paragraph, error) {
	comps, err := repo.subdirs(ctx, "pool")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan pool: %w", err)
	}

	result := make(map[string][]*apt.Paragraph, len(comps))

	for _, comp := range comps {
		compDir := "pool/" + comp
		prefix := compDir + "/"

		diskFiles := make(map[string]diskEntry)
		if err := repo.walk(ctx, compDir, ".deb", func(rel string, size int64, mtime time.Time) {
			diskFiles[prefix+rel] = newDiskEntry(size, mtime)
		}); err != nil {
			return nil, fmt.Errorf("walk %s: %w", compDir, err)
		}

		var paras []*apt.Paragraph
		if !force {
			var err error
			paras, err = loadState(ctx, repo, compDir, ".debrepo")
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
			para, err := processDeb(ctx, repo, filenameKey)
			if errors.Is(err, errUnreadable) {
				return nil, fmt.Errorf("pool component %s: %w", comp, err)
			}
			if err != nil {
				slog.Warn("skip pool deb", "file", filenameKey, "err", err)
				continue
			}
			para.Set("X-Mtime", diskFiles[filenameKey].mtime)
			paras = append(paras, para)
			newCount++
		}

		if newCount > 0 || removedCount > 0 || modifiedCount > 0 || force {
			slog.Info("pool state updated", "component", comp, "added", newCount, "removed", removedCount, "modified", modifiedCount)
			if err := saveState(ctx, repo, compDir, ".debrepo", paras); err != nil {
				slog.Warn("save pool state failed", "component", comp, "err", err)
			}
		}

		if len(paras) > 0 {
			result[comp] = paras
		}
	}

	return result, nil
}

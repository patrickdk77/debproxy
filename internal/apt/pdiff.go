package apt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// PDiffPatch describes one entry in a PDiff Index: the SHA256 of the Packages
// file at that historical point and the patch basename (without .gz).
// Patch file integrity is verified against the Release file, not this struct.
type PDiffPatch struct {
	PackagesSHA256 string
	Name           string // e.g. "2024-01-15-0230.43"
}

// PDiffIndex is a parsed Packages.diff/Index file.
type PDiffIndex struct {
	CurrentSHA256 string       // SHA256 of the current full Packages file
	Patches       []PDiffPatch // oldest-first; patch i transforms [i]→[i+1] (or current)
}

// PatchChain returns the patch names needed to bring a Packages file with the
// given SHA256 up to date, in application order. Returns nil if no chain exists
// (version too old or not in history).
func (idx *PDiffIndex) PatchChain(sha256 string) []string {
	for i, p := range idx.Patches {
		if strings.EqualFold(p.PackagesSHA256, sha256) {
			names := make([]string, len(idx.Patches)-i)
			for j := range names {
				names[j] = idx.Patches[i+j].Name
			}
			return names
		}
	}
	return nil
}

// ParsePDiffIndex parses a Packages.diff/Index file.
func ParsePDiffIndex(r io.Reader) (*PDiffIndex, error) {
	paras, err := ParseParagraphs(r)
	if err != nil {
		return nil, err
	}
	if len(paras) == 0 {
		return nil, fmt.Errorf("pdiff: empty Index")
	}
	p := paras[0]

	curField := strings.TrimSpace(p.Get("SHA256-Current"))
	if curField == "" {
		return nil, fmt.Errorf("pdiff: missing SHA256-Current")
	}
	cf := strings.Fields(curField)
	if len(cf) < 1 {
		return nil, fmt.Errorf("pdiff: invalid SHA256-Current: %q", curField)
	}

	hist := parsePDiffList(p.Get("SHA256-History"))
	patches := make([]PDiffPatch, len(hist))
	for i, h := range hist {
		patches[i] = PDiffPatch{PackagesSHA256: h[0], Name: h[2]}
	}
	return &PDiffIndex{CurrentSHA256: cf[0], Patches: patches}, nil
}

// parsePDiffList splits a multi-line deb822 field value (SHA256-History or
// SHA256-Patches) into rows of [hash, size, name] triples.
func parsePDiffList(raw string) [][3]string {
	var out [][3]string
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 {
			out = append(out, [3]string{f[0], f[1], f[2]})
		}
	}
	return out
}

// ---- Ed-script application ------------------------------------------------

// lineIdx is a read-only scaffold built from []RawPkg to support ed-patch
// application. It is never mutated and is discarded after all ops are applied.
type lineIdx struct {
	lines       []string
	stanzaOf    []int // 0-based line → stanza index; -1 for blank separator lines
	stanzaFirst []int // stanza index → first 0-based line of that stanza
}

func buildLineIdx(pkgs []RawPkg) lineIdx {
	total := 0
	for _, p := range pkgs {
		total += strings.Count(p.Raw, "\n") + 2
	}
	lines := make([]string, 0, total)
	stanzaOf := make([]int, 0, total)
	stanzaFirst := make([]int, len(pkgs))

	for i, p := range pkgs {
		stanzaFirst[i] = len(lines)
		raw := strings.TrimRight(p.Raw, "\n")
		for _, l := range strings.Split(raw, "\n") {
			lines = append(lines, l)
			stanzaOf = append(stanzaOf, i)
		}
		lines = append(lines, "")  // blank separator
		stanzaOf = append(stanzaOf, -1)
	}
	return lineIdx{lines: lines, stanzaOf: stanzaOf, stanzaFirst: stanzaFirst}
}

// stanzaAt converts a 1-based ed line number to a stanza index (-1 = separator).
func (li *lineIdx) stanzaAt(edLine int) int {
	i := edLine - 1
	if i < 0 || i >= len(li.stanzaOf) {
		return -1
	}
	return li.stanzaOf[i]
}

// stanzaRange returns the first and last stanza indices (inclusive) that have
// at least one content line in the 1-based range [addr1, addr2].
// Returns (-1, -1) if all lines in the range are blank separators.
func stanzaRange(li *lineIdx, addr1, addr2 int) (s1, s2 int) {
	s1, s2 = -1, -1
	for line := addr1; line <= addr2; line++ {
		s := li.stanzaAt(line)
		if s < 0 {
			continue
		}
		if s1 < 0 || s < s1 {
			s1 = s
		}
		if s > s2 {
			s2 = s
		}
	}
	return
}

// insertionStanza returns the stanza index after which 'a' text is inserted.
// Returns -1 to prepend (insert before all stanzas).
func insertionStanza(li *lineIdx, addr int) int {
	if addr == 0 {
		return -1
	}
	s := li.stanzaAt(addr)
	if s >= 0 {
		return s
	}
	// addr is a blank separator — insert after the preceding content stanza.
	if addr > 1 {
		return li.stanzaAt(addr - 1)
	}
	return -1
}

// rebuildStanza reconstructs the Raw text of stanza s after replacing the
// 1-based absolute line range [addr1, addr2] with replacement. The surrounding
// unchanged lines are read from the read-only li.lines.
func rebuildStanza(li *lineIdx, s, addr1, addr2 int, replacement string) string {
	first := li.stanzaFirst[s]
	var orig []string
	for i := first; i < len(li.lines); i++ {
		if li.lines[i] == "" {
			break
		}
		orig = append(orig, li.lines[i])
	}
	rel1 := addr1 - 1 - first
	rel2 := addr2 - 1 - first
	if rel1 < 0 {
		rel1 = 0
	}
	if rel2 >= len(orig) {
		rel2 = len(orig) - 1
	}
	var sb strings.Builder
	for _, l := range orig[:rel1] {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	sb.WriteString(replacement)
	for _, l := range orig[rel2+1:] {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// SerializeRawPkgs reconstructs the verbatim Packages file bytes from a
// []RawPkg slice. Each Raw field already ends with '\n'; one additional '\n'
// is appended to form the blank-line separator between stanzas, reproducing
// the exact byte layout of a standard Packages file.
func SerializeRawPkgs(pkgs []RawPkg) []byte {
	total := 0
	for _, p := range pkgs {
		total += len(p.Raw) + 1
	}
	buf := make([]byte, 0, total)
	for _, p := range pkgs {
		buf = append(buf, p.Raw...)
		buf = append(buf, '\n')
	}
	return buf
}

func sliceInsert(pkgs []RawPkg, pos int, newPkgs []RawPkg) []RawPkg {
	if pos < 0 {
		pos = 0
	}
	if pos > len(pkgs) {
		pos = len(pkgs)
	}
	out := make([]RawPkg, 0, len(pkgs)+len(newPkgs))
	out = append(out, pkgs[:pos]...)
	out = append(out, newPkgs...)
	out = append(out, pkgs[pos:]...)
	return out
}

// ---- Ed-script parsing -----------------------------------------------------

type edOp struct {
	addr1, addr2 int
	cmd          byte   // 'd', 'a', or 'c'
	text         string // replacement/append text for 'a' and 'c'
}

// ApplyEdPatch applies one decompressed ed-script patch to pkgs and returns the
// updated slice. The line index is built once and discarded when done.
func ApplyEdPatch(pkgs []RawPkg, patchData []byte) ([]RawPkg, error) {
	ops, err := parseEdOps(patchData)
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return pkgs, nil
	}
	li := buildLineIdx(pkgs)
	for _, op := range ops {
		var err error
		pkgs, err = applyEdOp(pkgs, &li, op)
		if err != nil {
			return nil, err
		}
	}
	return pkgs, nil
}

func parseEdOps(data []byte) ([]edOp, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var ops []edOp
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		op, err := parseEdCmd(line)
		if err != nil {
			return nil, err
		}
		if op.cmd == 'a' || op.cmd == 'c' {
			var sb strings.Builder
			for sc.Scan() {
				t := sc.Text()
				if t == "." {
					break
				}
				sb.WriteString(t)
				sb.WriteByte('\n')
			}
			op.text = sb.String()
		}
		ops = append(ops, op)
	}
	return ops, sc.Err()
}

func parseEdCmd(line string) (edOp, error) {
	if len(line) == 0 {
		return edOp{}, fmt.Errorf("ed: empty command line")
	}
	cmd := line[len(line)-1]
	if cmd != 'd' && cmd != 'a' && cmd != 'c' {
		return edOp{}, fmt.Errorf("ed: unknown command %q in %q", cmd, line)
	}
	addrs := line[:len(line)-1]
	var addr1, addr2 int
	if comma := strings.IndexByte(addrs, ','); comma >= 0 {
		a1, err1 := strconv.Atoi(addrs[:comma])
		a2, err2 := strconv.Atoi(addrs[comma+1:])
		if err1 != nil || err2 != nil {
			return edOp{}, fmt.Errorf("ed: bad address range in %q", line)
		}
		addr1, addr2 = a1, a2
	} else {
		a, err := strconv.Atoi(addrs)
		if err != nil {
			return edOp{}, fmt.Errorf("ed: bad address in %q", line)
		}
		addr1, addr2 = a, a
	}
	return edOp{addr1: addr1, addr2: addr2, cmd: cmd}, nil
}

func applyEdOp(pkgs []RawPkg, li *lineIdx, op edOp) ([]RawPkg, error) {
	switch op.cmd {
	case 'd':
		s1, s2 := stanzaRange(li, op.addr1, op.addr2)
		if s1 < 0 {
			return pkgs, nil
		}
		out := make([]RawPkg, 0, len(pkgs)-(s2-s1+1))
		out = append(out, pkgs[:s1]...)
		return append(out, pkgs[s2+1:]...), nil

	case 'a':
		newPkgs, err := ParsePackageRaws(strings.NewReader(op.text))
		if err != nil {
			return nil, fmt.Errorf("ed append at %d: %w", op.addr1, err)
		}
		ins := insertionStanza(li, op.addr1)
		return sliceInsert(pkgs, ins+1, newPkgs), nil

	case 'c':
		s1, s2 := stanzaRange(li, op.addr1, op.addr2)
		if s1 < 0 {
			return pkgs, nil
		}
		if s1 == s2 {
			// Change within one stanza — reconstruct from surrounding unchanged
			// lines in the read-only index, then parse the result.
			rebuilt := rebuildStanza(li, s1, op.addr1, op.addr2, op.text)
			newPkgs, err := ParsePackageRaws(strings.NewReader(rebuilt))
			if err != nil {
				return nil, fmt.Errorf("ed change at %d,%d: %w", op.addr1, op.addr2, err)
			}
			if len(newPkgs) == 0 {
				return nil, fmt.Errorf("ed change at %d,%d: empty result", op.addr1, op.addr2)
			}
			out := make([]RawPkg, 0, len(pkgs)-1+len(newPkgs))
			out = append(out, pkgs[:s1]...)
			out = append(out, newPkgs...)
			return append(out, pkgs[s1+1:]...), nil
		}
		newPkgs, err := ParsePackageRaws(strings.NewReader(op.text))
		if err != nil {
			return nil, fmt.Errorf("ed change at %d,%d: %w", op.addr1, op.addr2, err)
		}
		out := make([]RawPkg, 0, len(pkgs)-(s2-s1+1)+len(newPkgs))
		out = append(out, pkgs[:s1]...)
		out = append(out, newPkgs...)
		return append(out, pkgs[s2+1:]...), nil
	}
	return pkgs, nil
}

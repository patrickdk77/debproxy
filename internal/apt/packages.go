package apt

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RawPkg holds the fields extracted from one Packages index stanza that are
// needed for merge logic, plus the verbatim stanza text for index generation.
// This avoids building a full Paragraph (with its per-field map allocations)
// for the 350k+ packages that live in the IndexCache.
type RawPkg struct {
	Package    string
	Version    string
	Arch       string
	Section    string
	Filename   string // original upstream-relative path
	Size       int64
	SHA256     string
	SHA512     string
	Depends    string
	PreDepends string
	// Raw is the verbatim deb822 stanza text from the upstream Packages file.
	// Call WithFilename to produce the final stanza with the pool path.
	Raw string
}

// WithFilename returns the stanza text with the Filename field value replaced.
// It creates exactly one string allocation regardless of stanza size.
func (r RawPkg) WithFilename(newFilename string) string {
	const prefix = "\nFilename: "
	idx := strings.Index(r.Raw, prefix)
	if idx < 0 {
		// Filename is the first (or only) field  -- handle gracefully.
		return "Filename: " + newFilename + "\n" + r.Raw
	}
	rest := r.Raw[idx+len(prefix):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 {
		return r.Raw[:idx] + prefix + newFilename
	}
	return r.Raw[:idx] + prefix + newFilename + rest[end:]
}

// ParsePackageRaws parses a Packages index stream into RawPkg values.
// It extracts only the fields needed for merge and pool-path construction,
// preserving the full verbatim stanza text in RawPkg.Raw.
func ParsePackageRaws(r io.Reader) ([]RawPkg, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var result []RawPkg
	var raw strings.Builder
	var cur RawPkg
	nonEmpty := false
	var lastKey string

	flush := func() {
		if nonEmpty {
			cur.Raw = raw.String()
			result = append(result, cur)
		}
		raw.Reset()
		cur = RawPkg{}
		nonEmpty = false
		lastKey = ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		raw.WriteString(line)
		raw.WriteByte('\n')
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation line  -- only Depends/Pre-Depends need accumulation.
			cont := line[1:]
			switch lastKey {
			case "depends":
				cur.Depends += "\n" + cont
			case "pre-depends":
				cur.PreDepends += "\n" + cont
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return nil, fmt.Errorf("apt: invalid field line: %q", line)
		}
		val := strings.TrimSpace(line[colon+1:])
		lk := strings.ToLower(line[:colon])
		lastKey = lk
		nonEmpty = true
		switch lk {
		case "package":
			cur.Package = val
		case "version":
			cur.Version = val
		case "architecture":
			cur.Arch = val
		case "section":
			cur.Section = val
		case "filename":
			cur.Filename = val
		case "size":
			cur.Size = rawParseInt64(val)
		case "sha256":
			cur.SHA256 = val
		case "sha512":
			cur.SHA512 = val
		case "depends":
			cur.Depends = val
		case "pre-depends":
			cur.PreDepends = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return result, nil
}

func rawParseInt64(s string) int64 {
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// packagesFieldOrder is the conventional field order for Packages stanzas.
var packagesFieldOrder = []string{
	"Package", "Source", "Version", "Architecture", "Maintainer",
	"Installed-Size", "Provides", "Depends", "Pre-Depends", "Recommends",
	"Suggests", "Conflicts", "Breaks", "Replaces", "Section", "Priority",
	"Multi-Arch", "Homepage", "Description", "Description-md5",
}

// packagesFieldOrderLower is packagesFieldOrder pre-lowercased to avoid
// repeated strings.ToLower calls in the hot BuildPackagesStanza path.
var packagesFieldOrderLower = func() []string {
	out := make([]string, len(packagesFieldOrder))
	for i, k := range packagesFieldOrder {
		out[i] = strings.ToLower(k)
	}
	return out
}()

// BuildPackagesStanza converts a .deb control paragraph into a Packages stanza
// by appending the repository fields (Filename, Size, SHA256, SHA512) and
// ordering fields conventionally.
func BuildPackagesStanza(control *Paragraph, filename string, size int64, sha256, sha512 string) *Paragraph {
	out := NewParagraph()
	seen := map[string]bool{}
	for i, k := range packagesFieldOrder {
		lk := packagesFieldOrderLower[i]
		if v := control.GetLower(lk); v != "" {
			out.Set(k, v)
			seen[lk] = true
		}
	}
	// Non-standard fields: use LKeys() to avoid per-field ToLower in GetLower.
	keys := control.Keys()
	lkeys := control.LKeys()
	for i, lk := range lkeys {
		if !seen[lk] {
			out.Set(keys[i], control.GetLower(lk))
		}
	}
	out.Set("Filename", filename)
	out.Set("Size", strconv.FormatInt(size, 10))
	out.Set("SHA256", sha256)
	if sha512 != "" {
		out.Set("SHA512", sha512)
	}
	return out
}

// StanzaString renders a single paragraph to its deb822 string form.
// It pre-sizes the output buffer to avoid reallocations and writes multi-line
// field continuations directly without intermediate string allocations.
func StanzaString(p *Paragraph) (string, error) {
	// Pre-compute output size for a single allocation.
	size := 0
	for i, k := range p.keys {
		v := p.values[p.lkeys[i]]
		if strings.Contains(v, "\n") {
			size += len(k) + 2          // "Key:\n"
			size += len(v) + strings.Count(v, "\n") + 2 // indent each line + final \n
		} else {
			size += len(k) + 2 + len(v) + 1 // "Key: value\n"
		}
	}
	var b strings.Builder
	b.Grow(size)
	for i, k := range p.keys {
		v := p.values[p.lkeys[i]]
		if strings.Contains(v, "\n") {
			b.WriteString(k)
			b.WriteString(":\n")
			writeIndented(&b, v)
			b.WriteByte('\n')
		} else {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// writeIndented writes v to b with each line prefixed by a space, as required
// by deb822 for multi-line field values. No intermediate allocations.
func writeIndented(b *strings.Builder, v string) {
	for {
		b.WriteByte(' ')
		idx := strings.IndexByte(v, '\n')
		if idx < 0 {
			b.WriteString(v)
			return
		}
		b.WriteString(v[:idx])
		b.WriteByte('\n')
		v = v[idx+1:]
	}
}

// ParseStanza parses a single deb822 stanza from a string.
func ParseStanza(s string) (*Paragraph, error) {
	paras, err := ParseParagraphs(strings.NewReader(s))
	if err != nil {
		return nil, err
	}
	if len(paras) == 0 {
		return nil, fmt.Errorf("empty stanza")
	}
	return paras[0], nil
}

// Package apt parses and writes Debian repository metadata (deb822 control
// format, Release files, and Packages indices).
package apt

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Paragraph is a single deb822 stanza preserving field order.
type Paragraph struct {
	keys   []string
	lkeys  []string // lowercase of keys, parallel to keys
	values map[string]string
}

// NewParagraph returns an empty paragraph pre-sized for ~25 fields (typical
// Packages stanza size) to avoid slice/map growth in BuildPackagesStanza.
func NewParagraph() *Paragraph {
	return &Paragraph{
		keys:   make([]string, 0, 24),
		lkeys:  make([]string, 0, 24),
		values: make(map[string]string, 24),
	}
}

// Get returns the value for a field (case-insensitive), or "".
func (p *Paragraph) Get(key string) string {
	return p.values[strings.ToLower(key)]
}

// GetLower returns the value for a pre-lowercased field key (no allocation).
func (p *Paragraph) GetLower(lkey string) string {
	return p.values[lkey]
}

// Has reports whether the field is present.
func (p *Paragraph) Has(key string) bool {
	_, ok := p.values[strings.ToLower(key)]
	return ok
}

// Set adds or replaces a field, preserving first-seen order.
func (p *Paragraph) Set(key, value string) {
	lk := strings.ToLower(key)
	if _, ok := p.values[lk]; !ok {
		p.keys = append(p.keys, key)
		p.lkeys = append(p.lkeys, lk)
	}
	p.values[lk] = value
}

// Keys returns field names in order.
func (p *Paragraph) Keys() []string {
	return append([]string(nil), p.keys...)
}

// LKeys returns pre-lowercased field names in the same order as Keys.
func (p *Paragraph) LKeys() []string {
	return append([]string(nil), p.lkeys...)
}

// WriteTo renders the paragraph in deb822 form (without trailing blank line).
func (p *Paragraph) WriteTo(w io.Writer) (int64, error) {
	var n int64
	for i, k := range p.keys {
		v := p.values[p.lkeys[i]]
		var line string
		if strings.Contains(v, "\n") {
			// Trim a leading \n that arises when a field has an empty first line
			// (e.g. "Checksums-Sha256:\n hash size file") and ParseParagraphs stores
			// it as "\nhash size file". Without the trim, WriteTo would emit a blank
			// continuation line before the first real entry.
			line = k + ":\n" + indentContinuation(strings.TrimPrefix(v, "\n")) + "\n"
		} else {
			line = k + ": " + v + "\n"
		}
		m, err := io.WriteString(w, line)
		n += int64(m)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func indentContinuation(v string) string {
	lines := strings.Split(v, "\n")
	for i, l := range lines {
		lines[i] = " " + l
	}
	return strings.Join(lines, "\n")
}

// ParseParagraphs reads all deb822 stanzas from r.
func ParseParagraphs(r io.Reader) ([]*Paragraph, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var paras []*Paragraph
	cur := NewParagraph()
	var lastKey string
	nonEmpty := false

	flush := func() {
		if nonEmpty {
			paras = append(paras, cur)
		}
		cur = NewParagraph()
		lastKey = ""
		nonEmpty = false
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey == "" {
				return nil, fmt.Errorf("continuation line with no preceding field: %q", line)
			}
			cont := strings.TrimRight(line[1:], "\r")
			existing := cur.Get(lastKey)
			cur.values[strings.ToLower(lastKey)] = existing + "\n" + cont
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid field line: %q", line)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		cur.Set(key, val)
		lastKey = key
		nonEmpty = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return paras, nil
}

// WriteParagraphs renders stanzas separated by blank lines.
func WriteParagraphs(w io.Writer, paras []*Paragraph) error {
	for i, p := range paras {
		if _, err := p.WriteTo(w); err != nil {
			return err
		}
		if i != len(paras)-1 {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
	}
	return nil
}

// SortPackages orders paragraphs by Package then Version for stable output.
func SortPackages(paras []*Paragraph) {
	sort.SliceStable(paras, func(i, j int) bool {
		if a, b := paras[i].Get("Package"), paras[j].Get("Package"); a != b {
			return a < b
		}
		return paras[i].Get("Version") < paras[j].Get("Version")
	})
}

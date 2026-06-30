package apt

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// FileEntry is one row of a Release file's hash list.
type FileEntry struct {
	Path   string
	Size   int64
	SHA256 string
	SHA512 string
}

// Release is a parsed Debian Release file.
type Release struct {
	Para  *Paragraph
	Files map[string]FileEntry // keyed by path
}

// Get returns a top-level Release field.
func (r *Release) Get(key string) string { return r.Para.Get(key) }

// ParseRelease parses a Release/InRelease body (signature already stripped).
func ParseRelease(r io.Reader) (*Release, error) {
	paras, err := ParseParagraphs(r)
	if err != nil {
		return nil, err
	}
	if len(paras) == 0 {
		return nil, fmt.Errorf("empty Release")
	}
	p := paras[0]
	rel := &Release{Para: p, Files: map[string]FileEntry{}}

	parseHashSection(rel, p.Get("SHA256"), func(e *FileEntry, hash string) { e.SHA256 = hash })
	parseHashSection(rel, p.Get("SHA512"), func(e *FileEntry, hash string) { e.SHA512 = hash })

	return rel, nil
}

func parseHashSection(rel *Release, section string, set func(*FileEntry, string)) {
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		filePath := fields[2]
		e := rel.Files[filePath]
		e.Path = filePath
		e.Size = size
		set(&e, fields[0])
		rel.Files[filePath] = e
	}
}

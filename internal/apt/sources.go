package apt

import (
	"bufio"
	"io"
	"strings"
)

// RawSrc holds the fields extracted from one Sources index stanza needed for
// generating our Sources index and for pull-through downloads.
type RawSrc struct {
	Package   string
	Version   string
	Directory string   // upstream-relative directory path
	Files     []RawSrcFile
	Raw       string   // verbatim deb822 stanza text from upstream
}

// RawSrcFile is one file listed in a Sources stanza's Checksums-Sha256: field.
type RawSrcFile struct {
	Filename string
	Size     int64
	SHA256   string
}

// WithDirectory returns the stanza text with the Directory field replaced.
func (r RawSrc) WithDirectory(newDir string) string {
	const prefix = "\nDirectory: "
	idx := strings.Index(r.Raw, prefix)
	if idx < 0 {
		if strings.HasPrefix(r.Raw, "Directory: ") {
			end := strings.IndexByte(r.Raw, '\n')
			if end < 0 {
				return "Directory: " + newDir
			}
			return "Directory: " + newDir + r.Raw[end:]
		}
		return r.Raw + "Directory: " + newDir + "\n"
	}
	rest := r.Raw[idx+len(prefix):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 {
		return r.Raw[:idx] + prefix + newDir
	}
	return r.Raw[:idx] + prefix + newDir + rest[end:]
}

// ParseSourceRaws parses a Sources index stream into RawSrc values. Only the
// fields needed for pull-through and index generation are extracted; the full
// verbatim stanza is preserved in RawSrc.Raw.
func ParseSourceRaws(r io.Reader) ([]RawSrc, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var result []RawSrc
	var raw strings.Builder
	var cur RawSrc
	nonEmpty := false
	var lastKey string

	flush := func() {
		if nonEmpty {
			cur.Raw = raw.String()
			result = append(result, cur)
		}
		raw.Reset()
		cur = RawSrc{}
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
			if lastKey == "checksums-sha256" {
				parts := strings.Fields(line)
				if len(parts) == 3 {
					cur.Files = append(cur.Files, RawSrcFile{
						SHA256:   parts[0],
						Size:     rawParseInt64(parts[1]),
						Filename: parts[2],
					})
				}
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
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
		case "directory":
			cur.Directory = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return result, nil
}

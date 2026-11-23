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
	Directory string // upstream-relative directory path
	Files     []RawSrcFile
	Raw       string // verbatim deb822 stanza text from upstream
}

// RawSrcFile is one file listed in a Sources stanza's Checksums-Sha256: field.
type RawSrcFile struct {
	Filename string
	Size     int64
	MD5      string
	SHA1     string
	SHA256   string
	SHA512   string
}

func (f RawSrcFile) Hashes() Hashes {
	return Hashes{MD5: f.MD5, SHA1: f.SHA1, SHA256: f.SHA256, SHA512: f.SHA512}
}

func (f *RawSrcFile) set(algo HashAlgo, digest string) {
	h := f.Hashes()
	h.Set(algo, digest)
	f.MD5, f.SHA1, f.SHA256, f.SHA512 = h.MD5, h.SHA1, h.SHA256, h.SHA512
}

// srcChecksumFields maps the stanza fields that list files to the digest
// each one carries.
var srcChecksumFields = map[string]HashAlgo{
	"files":            HashMD5,
	"checksums-sha1":   HashSHA1,
	"checksums-sha256": HashSHA256,
	"checksums-sha512": HashSHA512,
}

// addFile records one line of a checksum section, merging it into the
// entry for the same filename from an earlier section.
func (r *RawSrc) addFile(algo HashAlgo, digest string, size int64, name string) {
	for i := range r.Files {
		if r.Files[i].Filename == name {
			r.Files[i].set(algo, digest)
			if r.Files[i].Size == 0 {
				r.Files[i].Size = size
			}
			return
		}
	}
	f := RawSrcFile{Filename: name, Size: size}
	f.set(algo, digest)
	r.Files = append(r.Files, f)
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
			if algo, ok := srcChecksumFields[lastKey]; ok {
				if parts := strings.Fields(line); len(parts) == 3 {
					cur.addFile(algo, parts[0], rawParseInt64(parts[1]), parts[2])
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

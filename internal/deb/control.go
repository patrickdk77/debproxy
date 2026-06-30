package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/debproxy/debproxy/internal/apt"
)

// Control describes parsed debian control fields.
type Control struct {
	Package      string
	Version      string
	Architecture string
	Section      string
	Depends      string
	PreDepends   string
}

// controlBytes returns the raw control file contents from a .deb.
func controlBytes(r io.ReadSeeker) ([]byte, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	names, err := readARMemberNames(r)
	if err != nil {
		return nil, fmt.Errorf("read ar: %w", err)
	}
	var controlMember string
	for _, name := range names {
		if strings.HasPrefix(name, "control.tar") {
			controlMember = name
			break
		}
	}
	if controlMember == "" {
		return nil, fmt.Errorf("control.tar not found")
	}
	member, err := openARMember(r, controlMember)
	if err != nil {
		return nil, err
	}
	return readControlTar(member, controlMember)
}

// ParseControl extracts key control metadata from a .deb file.
func ParseControl(r io.ReadSeeker) (Control, error) {
	data, err := controlBytes(r)
	if err != nil {
		return Control{}, err
	}
	return parseControlFile(data)
}

// ControlParagraph returns the full control stanza of a .deb as a deb822 paragraph.
func ControlParagraph(r io.ReadSeeker) (*apt.Paragraph, error) {
	data, err := controlBytes(r)
	if err != nil {
		return nil, err
	}
	paras, err := apt.ParseParagraphs(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	if len(paras) == 0 {
		return nil, fmt.Errorf("empty control stanza")
	}
	return paras[0], nil
}

func readControlTar(r io.Reader, name string) ([]byte, error) {
	var inner io.Reader = r
	switch {
	case strings.HasSuffix(name, ".bz2"):
		inner = bzip2.NewReader(r)
	case strings.HasSuffix(name, ".gz"):
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		inner = gz
	case strings.HasSuffix(name, ".xz"):
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		inner = xr
	case strings.HasSuffix(name, ".zst"):
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		inner = zr
	}
	tr := tar.NewReader(inner)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == "./control" || hdr.Name == "control" {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("control file not found in %s", name)
}

func parseControlFile(data []byte) (Control, error) {
	fields := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	if err := scanner.Err(); err != nil {
		return Control{}, err
	}
	c := Control{
		Package:      fields["Package"],
		Version:      fields["Version"],
		Architecture: fields["Architecture"],
		Section:      fields["Section"],
		Depends:      fields["Depends"],
		PreDepends:   fields["Pre-Depends"],
	}
	if c.Package == "" || c.Version == "" {
		return Control{}, fmt.Errorf("missing Package or Version in control")
	}
	return c, nil
}

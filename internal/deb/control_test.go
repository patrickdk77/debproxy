package deb_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/debproxy/debproxy/internal/deb"
	"github.com/ulikunitz/xz"
)

// buildDeb creates a minimal .deb AR archive with a control.tar compressed
// by the supplied compressor function.
func buildDeb(t *testing.T, compress func(io.Writer) io.WriteCloser, ext string) *bytes.Buffer {
	t.Helper()

	// Build control.tar in memory.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	control := []byte("Package: testpkg\nVersion: 1.0\nArchitecture: all\n")
	_ = tw.WriteHeader(&tar.Header{Name: "./control", Size: int64(len(control)), Mode: 0644})
	tw.Write(control)
	tw.Close()

	// Compress the tar.
	var compBuf bytes.Buffer
	cw := compress(&compBuf)
	cw.Write(tarBuf.Bytes())
	cw.Close()

	memberName := "control.tar" + ext
	memberData := compBuf.Bytes()

	// Build AR archive.
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeARMember(&ar, "debian-binary", []byte("2.0\n"))
	writeARMember(&ar, memberName, memberData)
	writeARMember(&ar, "data.tar.gz", []byte{0x1f, 0x8b, 0x08, 0x00}) // fake, not read
	return &ar
}

func writeARMember(w *bytes.Buffer, name string, data []byte) {
	hdr := make([]byte, 60)
	copy(hdr[0:], name+"/")
	for i := len(name) + 1; i < 16; i++ {
		hdr[i] = ' '
	}
	copy(hdr[16:], "0           ") // mtime
	copy(hdr[28:], "0     ")       // uid
	copy(hdr[34:], "0     ")       // gid
	copy(hdr[40:], "100644  ")     // mode
	sz := len(data)
	copy(hdr[48:], fmt.Sprintf("%-10d", sz))
	hdr[58] = '`'
	hdr[59] = '\n'
	w.Write(hdr)
	w.Write(data)
	if sz%2 == 1 {
		w.WriteByte(0)
	}
}

func TestControlParagraphGz(t *testing.T) {
	ar := buildDeb(t, func(w io.Writer) io.WriteCloser { gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed); return gz }, ".gz")
	p, err := deb.ControlParagraph(bytes.NewReader(ar.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Get("Package") != "testpkg" {
		t.Fatalf("got %q", p.Get("Package"))
	}
}

func TestControlParagraphXz(t *testing.T) {
	ar := buildDeb(t, func(w io.Writer) io.WriteCloser {
		xw, _ := xz.NewWriter(w)
		return xw
	}, ".xz")
	p, err := deb.ControlParagraph(bytes.NewReader(ar.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Get("Package") != "testpkg" {
		t.Fatalf("got %q", p.Get("Package"))
	}
}

// TestControlParagraph_xz_file simulates the rebuild code path where an
// *os.File is passed to ControlParagraph. Previously openARMember returned
// io.LimitReader(*os.File, n), which is non-seekable  -- some xz streams fail
// in the ulikunitz/xz streaming mode. The fix buffers the member into a
// bytes.Reader so the decompressor gets a seekable reader.
func TestControlParagraphXzFile(t *testing.T) {
	ar := buildDeb(t, func(w io.Writer) io.WriteCloser {
		xw, _ := xz.NewWriter(w)
		return xw
	}, ".xz")

	f, err := os.CreateTemp("", "debtest-*.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	f.Write(ar.Bytes())
	f.Seek(0, io.SeekStart)

	// Pass *os.File directly  -- same as toReadSeeker returns for filesystem store.
	p, err := deb.ControlParagraph(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Get("Package") != "testpkg" {
		t.Fatalf("got %q", p.Get("Package"))
	}
}

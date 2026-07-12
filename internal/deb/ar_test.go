package deb_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/debproxy/debproxy/internal/deb"
)

// buildArHeader builds one 60-byte ar(5) member header with the given name
// and raw size field (left as given, so malformed values can be injected).
func buildArHeader(name, size string) []byte {
	h := make([]byte, 60)
	copy(h[0:16], fmt.Sprintf("%-16s", name))
	copy(h[16:28], fmt.Sprintf("%-12s", "0"))
	copy(h[28:34], fmt.Sprintf("%-6s", "0"))
	copy(h[34:40], fmt.Sprintf("%-6s", "0"))
	copy(h[40:48], fmt.Sprintf("%-8s", "100644"))
	copy(h[48:58], fmt.Sprintf("%-10s", size))
	copy(h[58:60], "`\n")
	return h
}

// TestControlParagraph_NegativeArSize verifies that a corrupted .deb with a
// negative ar member size returns an error instead of panicking (previously
// `make([]byte, size)` with a negative size would panic with
// "makeslice: len out of range").
func TestControlParagraphNegativeArSize(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	buf.Write(buildArHeader("control.tar.gz", "-1"))

	_, err := deb.ControlParagraph(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for negative ar member size, got nil")
	}
}

// TestParseControl_NegativeArSize is the same scenario through ParseControl.
func TestParseControlNegativeArSize(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	buf.Write(buildArHeader("control.tar.gz", "-1"))

	_, err := deb.ParseControl(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for negative ar member size, got nil")
	}
}

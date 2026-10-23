package deb

import (
	"archive/tar"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// arHeaderFor builds one 60-byte ar member header claiming the given
// size. Only the fields openARMember reads are populated.
func arHeaderFor(name string, size int64) []byte {
	h := make([]byte, 60)
	for i := range h {
		h[i] = ' '
	}
	copy(h[0:16], name+"/")
	copy(h[48:58], fmt.Sprintf("%d", size))
	copy(h[58:60], "`\n")
	return h
}

// TestOpenARMemberRejectsOversizedHeader is the regression test for the
// unbounded allocation: a header claiming more than the cap must be
// refused before any memory is reserved for it.
func TestOpenARMemberRejectsOversizedHeader(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(arGlobalHeader)
	buf.Write(arHeaderFor("control.tar", maxARMemberBytes+1))

	_, err := openARMember(bytes.NewReader(buf.Bytes()), "control.tar")
	if err == nil {
		t.Fatal("oversized member accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error does not name the limit: %v", err)
	}
}

// TestOpenARMemberRejectsTenDigitSize covers the worst case the field
// format allows: ten decimal digits, close to ten gigabytes.
func TestOpenARMemberRejectsTenDigitSize(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(arGlobalHeader)
	buf.Write(arHeaderFor("control.tar", 9999999999))

	if _, err := openARMember(bytes.NewReader(buf.Bytes()), "control.tar"); err == nil {
		t.Fatal("ten-digit size accepted")
	}
}

func TestOpenARMemberAcceptsSizeAtCap(t *testing.T) {
	// A member exactly at the cap is legal; the body is short so the
	// read fails on EOF, not on the size check. That failure must not
	// mention the limit.
	var buf bytes.Buffer
	buf.WriteString(arGlobalHeader)
	buf.Write(arHeaderFor("control.tar", maxARMemberBytes))
	buf.WriteString("short")

	_, err := openARMember(bytes.NewReader(buf.Bytes()), "control.tar")
	if err == nil {
		t.Fatal("expected a read error for a truncated body")
	}
	if strings.Contains(err.Error(), "exceeds") {
		t.Errorf("size exactly at cap was rejected by the limit: %v", err)
	}
}

func TestOpenARMemberReadsSmallMemberIntact(t *testing.T) {
	payload := []byte("hello control")
	var buf bytes.Buffer
	buf.WriteString(arGlobalHeader)
	buf.Write(arHeaderFor("control.tar", int64(len(payload))))
	buf.Write(payload)

	r, err := openARMember(bytes.NewReader(buf.Bytes()), "control.tar")
	if err != nil {
		t.Fatalf("openARMember: %v", err)
	}
	var got bytes.Buffer
	if _, err := got.ReadFrom(r); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("got %q, want %q", got.Bytes(), payload)
	}
}

// controlTarWith builds an uncompressed control.tar whose control entry
// has the given size.
func controlTarWith(t *testing.T, size int) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(size)}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(bytes.Repeat([]byte("a"), size)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestReadControlTarRejectsOversizedControl: the control file inside
// control.tar must be bounded on its own, since the ar cap only sees
// the compressed member.
func TestReadControlTarRejectsOversizedControl(t *testing.T) {
	data := controlTarWith(t, maxControlBytes+1)
	if _, err := readControlTar(bytes.NewReader(data), "control.tar"); err == nil {
		t.Fatal("oversized control file accepted")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error does not name the limit: %v", err)
	}
}

func TestReadControlTarAcceptsControlAtCap(t *testing.T) {
	data := controlTarWith(t, maxControlBytes)
	got, err := readControlTar(bytes.NewReader(data), "control.tar")
	if err != nil {
		t.Fatalf("control exactly at cap rejected: %v", err)
	}
	if len(got) != maxControlBytes {
		t.Fatalf("got %d bytes, want %d", len(got), maxControlBytes)
	}
}

func TestReadControlTarReadsSmallControl(t *testing.T) {
	data := controlTarWith(t, 64)
	got, err := readControlTar(bytes.NewReader(data), "control.tar")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("got %d bytes, want 64", len(got))
	}
}

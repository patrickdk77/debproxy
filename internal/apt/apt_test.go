package apt_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
)

func TestParseParagraphsAndRoundTrip(t *testing.T) {
	input := "Package: apt\nVersion: 2.6.1\nDepends: libc6, libgcc-s1\n\nPackage: bash\nVersion: 5.2\n"
	paras, err := apt.ParseParagraphs(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(paras) != 2 {
		t.Fatalf("expected 2 paragraphs, got %d", len(paras))
	}
	if paras[0].Get("Package") != "apt" || paras[0].Get("version") != "2.6.1" {
		t.Fatalf("unexpected fields: %+v", paras[0])
	}

	var buf bytes.Buffer
	if err := apt.WriteParagraphs(&buf, paras); err != nil {
		t.Fatal(err)
	}
	reparsed, err := apt.ParseParagraphs(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(reparsed) != 2 || reparsed[1].Get("Package") != "bash" {
		t.Fatalf("round trip failed: %+v", reparsed)
	}
}

func TestParagraphJSONRoundTrip(t *testing.T) {
	input := "Package: apt\nVersion: 2.6.1\nDepends: libc6, libgcc-s1\n"
	paras, err := apt.ParseParagraphs(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	orig := paras[0]

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var got apt.Paragraph
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if got.Get("Package") != "apt" || got.Get("Version") != "2.6.1" || got.Get("Depends") != "libc6, libgcc-s1" {
		t.Fatalf("unexpected fields after round trip: %+v", got)
	}
	if !reflect.DeepEqual(got.Keys(), orig.Keys()) {
		t.Fatalf("field order not preserved: got %v want %v", got.Keys(), orig.Keys())
	}
}

func TestReleaseJSONRoundTrip(t *testing.T) {
	input := `Origin: Debian
Suite: trixie
SHA256:
 aaaa 100 main/binary-amd64/Packages
`
	rel, err := apt.ParseRelease(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(rel)
	if err != nil {
		t.Fatalf("marshal release: %v", err)
	}

	var got apt.Release
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal release: %v", err)
	}
	if got.Get("Origin") != "Debian" || got.Get("Suite") != "trixie" {
		t.Fatalf("unexpected release fields: %+v", got)
	}
	entry, ok := got.Files["main/binary-amd64/Packages"]
	if !ok || entry.SHA256 != "aaaa" || entry.Size != 100 {
		t.Fatalf("unexpected file entry: %+v", entry)
	}
}

func TestParseRelease(t *testing.T) {
	input := `Origin: Debian
Suite: trixie
Codename: trixie
Architectures: amd64 arm64
Components: main
SHA256:
 aaaa 1234 main/binary-amd64/Packages
 bbbb 5678 main/binary-amd64/Packages.gz
`
	rel, err := apt.ParseRelease(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if rel.Get("Codename") != "trixie" {
		t.Fatalf("expected codename trixie, got %q", rel.Get("Codename"))
	}
	entry, ok := rel.Files["main/binary-amd64/Packages"]
	if !ok {
		t.Fatal("missing Packages entry")
	}
	if entry.SHA256 != "aaaa" || entry.Size != 1234 {
		t.Fatalf("unexpected entry %+v", entry)
	}
}

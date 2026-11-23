package deb822store

import (
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
)

func TestSourceEntryParagraphRoundTripsEveryDigest(t *testing.T) {
	e := model.SourceEntry{
		OS: "debian", Codename: "trixie", Component: "main", Package: "a", Version: "1",
		Upstream: "up", UpstreamDir: "pool/main/a/a",
		Files: []model.SourceFile{
			{Filename: "a_1.dsc", Size: 10, MD5: "m", SHA1: "s1", SHA256: "s2", SHA512: "s5"},
			{Filename: "a_1.tar.xz", Size: 20, MD5: "m2", SHA1: "s1b"},
		},
	}
	p := sourceEntryToParagraph(e)
	got := sourceEntryFromParagraph("debian", "trixie", "main", p)
	if len(got.Files) != 2 {
		t.Fatalf("got %d files", len(got.Files))
	}
	for i := range e.Files {
		if got.Files[i] != e.Files[i] {
			t.Errorf("file %d: %+v != %+v", i, got.Files[i], e.Files[i])
		}
	}
	if algo, _ := got.Files[1].Hashes().Best(); algo != apt.HashSHA1 {
		t.Errorf("weak-only file Best() = %s after round trip", algo)
	}
}

// Lines written before the extra digests existed carry three fields and
// must still load.
func TestSourceEntryParagraphReadsLegacyThreeFieldLines(t *testing.T) {
	p := apt.NewParagraph()
	p.Set("Package", "a")
	p.Set("Version", "1")
	p.Set("X-Debproxy-File-0", "a_1.dsc 10 s2")
	got := sourceEntryFromParagraph("debian", "trixie", "main", p)
	if len(got.Files) != 1 {
		t.Fatalf("got %d files", len(got.Files))
	}
	want := model.SourceFile{Filename: "a_1.dsc", Size: 10, SHA256: "s2"}
	if got.Files[0] != want {
		t.Fatalf("%+v != %+v", got.Files[0], want)
	}
}

func TestSourceEntryParagraphStopsAtMalformedLine(t *testing.T) {
	p := apt.NewParagraph()
	p.Set("X-Debproxy-File-0", "a_1.dsc 10 s2 s5 s1 m")
	p.Set("X-Debproxy-File-1", "broken 10")
	p.Set("X-Debproxy-File-2", "c.dsc 10 s2")
	got := sourceEntryFromParagraph("debian", "trixie", "main", p)
	if len(got.Files) != 1 {
		t.Fatalf("got %d files, want the one before the malformed line", len(got.Files))
	}
}

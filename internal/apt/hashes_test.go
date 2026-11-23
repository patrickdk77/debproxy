package apt_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
)

var payload = []byte("the quick brown fox")

func digest(algo apt.HashAlgo, data []byte) string {
	switch algo {
	case apt.HashMD5:
		s := md5.Sum(data)
		return hex.EncodeToString(s[:])
	case apt.HashSHA1:
		s := sha1.Sum(data)
		return hex.EncodeToString(s[:])
	case apt.HashSHA256:
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	case apt.HashSHA512:
		s := sha512.Sum512(data)
		return hex.EncodeToString(s[:])
	}
	panic(algo)
}

func allHashes(data []byte) apt.Hashes {
	return apt.Hashes{
		MD5:    digest(apt.HashMD5, data),
		SHA1:   digest(apt.HashSHA1, data),
		SHA256: digest(apt.HashSHA256, data),
		SHA512: digest(apt.HashSHA512, data),
	}
}

func TestHashesBestIsStrongestPresent(t *testing.T) {
	cases := []struct {
		h    apt.Hashes
		want apt.HashAlgo
	}{
		{apt.Hashes{MD5: "m", SHA1: "1", SHA256: "2", SHA512: "5"}, apt.HashSHA512},
		{apt.Hashes{MD5: "m", SHA1: "1", SHA256: "2"}, apt.HashSHA256},
		{apt.Hashes{MD5: "m", SHA1: "1"}, apt.HashSHA1},
		{apt.Hashes{MD5: "m"}, apt.HashMD5},
		{apt.Hashes{SHA512: "5", MD5: "m"}, apt.HashSHA512},
	}
	for _, c := range cases {
		algo, d := c.h.Best()
		if algo != c.want || d != c.h.Get(c.want) {
			t.Errorf("%+v: Best() = %s %q, want %s", c.h, algo, d, c.want)
		}
	}
	if algo, d := (apt.Hashes{}).Best(); algo != "" || d != "" {
		t.Errorf("empty Best() = %q %q", algo, d)
	}
	if !(apt.Hashes{}).Empty() || (apt.Hashes{MD5: "m"}).Empty() {
		t.Error("Empty() wrong")
	}
}

func TestHashesVerifyUsesStrongestOnly(t *testing.T) {
	h := allHashes(payload)
	if err := h.Verify(payload); err != nil {
		t.Fatalf("all correct: %v", err)
	}
	// A wrong SHA512 fails even though every weaker digest is right.
	bad := h
	bad.SHA512 = strings.Repeat("0", 128)
	if err := bad.Verify(payload); !errors.Is(err, apt.ErrDigestMismatch) {
		t.Fatalf("wrong SHA512 beside right weaker digests: err = %v", err)
	}
	// Wrong weaker digests are never consulted when SHA512 is right.
	loose := h
	loose.MD5, loose.SHA1, loose.SHA256 = "x", "y", "z"
	if err := loose.Verify(payload); err != nil {
		t.Fatalf("right SHA512 beside wrong weaker digests: %v", err)
	}
}

func TestHashesVerifyFallsBackOnlyWhenStrongerAbsent(t *testing.T) {
	for _, algo := range []apt.HashAlgo{apt.HashSHA256, apt.HashSHA1, apt.HashMD5} {
		var h apt.Hashes
		h.Set(algo, digest(algo, payload))
		if err := h.Verify(payload); err != nil {
			t.Errorf("%s alone, correct: %v", algo, err)
		}
		h.Set(algo, digest(algo, []byte("other")))
		err := h.Verify(payload)
		if !errors.Is(err, apt.ErrDigestMismatch) {
			t.Errorf("%s alone, wrong: err = %v", algo, err)
		}
		if err != nil && !strings.Contains(err.Error(), string(algo)) {
			t.Errorf("%s mismatch error does not name the algorithm: %v", algo, err)
		}
	}
}

func TestHashesVerifyEmptyIsAnError(t *testing.T) {
	if err := (apt.Hashes{}).Verify(payload); !errors.Is(err, apt.ErrNoDigest) {
		t.Fatalf("err = %v, want ErrNoDigest", err)
	}
}

func TestHashesVerifyIsCaseInsensitive(t *testing.T) {
	h := apt.Hashes{SHA256: strings.ToUpper(digest(apt.HashSHA256, payload))}
	if err := h.Verify(payload); err != nil {
		t.Fatal(err)
	}
}

func TestNewHashCoversEveryPreference(t *testing.T) {
	for _, algo := range apt.HashPreference {
		hh := apt.NewHash(algo)
		hh.Write(payload)
		if got := hex.EncodeToString(hh.Sum(nil)); got != digest(algo, payload) {
			t.Errorf("%s: NewHash digest %s != %s", algo, got, digest(algo, payload))
		}
	}
}

func TestParseReleaseReadsEveryHashSection(t *testing.T) {
	input := "Origin: Debian\nSuite: trixie\nCodename: trixie\n" +
		"MD5Sum:\n mmmm 1234 main/binary-amd64/Packages\n" +
		"SHA1:\n 1111 1234 main/binary-amd64/Packages\n" +
		"SHA256:\n 2222 1234 main/binary-amd64/Packages\n" +
		"SHA512:\n 5555 1234 main/binary-amd64/Packages\n"
	rel, err := apt.ParseRelease(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	e := rel.Files["main/binary-amd64/Packages"]
	want := apt.Hashes{MD5: "mmmm", SHA1: "1111", SHA256: "2222", SHA512: "5555"}
	if e.Hashes() != want || e.Size != 1234 {
		t.Fatalf("entry %+v, want hashes %+v size 1234", e, want)
	}
}

func TestParseReleaseWeakOnlyStillListsFiles(t *testing.T) {
	input := "Suite: old\nMD5Sum:\n mmmm 10 main/binary-amd64/Packages\n"
	rel, err := apt.ParseRelease(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := rel.Files["main/binary-amd64/Packages"]
	if !ok {
		t.Fatal("MD5Sum-only Release lists no files")
	}
	if algo, d := e.Hashes().Best(); algo != apt.HashMD5 || d != "mmmm" {
		t.Fatalf("Best() = %s %q", algo, d)
	}
}

func TestParsePackageRawsReadsWeakHashes(t *testing.T) {
	in := "Package: a\nVersion: 1\nArchitecture: amd64\nFilename: pool/a.deb\nSize: 3\nMD5sum: mm\nSHA1: s1\nSHA256: s2\nSHA512: s5\n\n"
	pkgs, err := apt.ParsePackageRaws(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d stanzas", len(pkgs))
	}
	want := apt.Hashes{MD5: "mm", SHA1: "s1", SHA256: "s2", SHA512: "s5"}
	if pkgs[0].Hashes() != want {
		t.Fatalf("hashes %+v, want %+v", pkgs[0].Hashes(), want)
	}
}

func TestParseSourceRawsMergesChecksumSectionsByFilename(t *testing.T) {
	in := "Package: a\nVersion: 1\nDirectory: pool/main/a/a\n" +
		"Files:\n m1 10 a_1.dsc\n m2 20 a_1.tar.xz\n" +
		"Checksums-Sha1:\n s1a 10 a_1.dsc\n s1b 20 a_1.tar.xz\n" +
		"Checksums-Sha256:\n s2a 10 a_1.dsc\n" +
		"Checksums-Sha512:\n s5a 10 a_1.dsc\n\n"
	srcs, err := apt.ParseSourceRaws(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || len(srcs[0].Files) != 2 {
		t.Fatalf("got %d sources with %d files", len(srcs), len(srcs[0].Files))
	}
	byName := map[string]apt.RawSrcFile{}
	for _, f := range srcs[0].Files {
		byName[f.Filename] = f
	}
	dsc := byName["a_1.dsc"]
	if dsc.Hashes() != (apt.Hashes{MD5: "m1", SHA1: "s1a", SHA256: "s2a", SHA512: "s5a"}) || dsc.Size != 10 {
		t.Errorf("dsc = %+v", dsc)
	}
	// The tarball appears in Files and Checksums-Sha1 only: it is listed
	// once, with SHA1 as its strongest digest.
	tar := byName["a_1.tar.xz"]
	if tar.Hashes() != (apt.Hashes{MD5: "m2", SHA1: "s1b"}) || tar.Size != 20 {
		t.Errorf("tar = %+v", tar)
	}
	if algo, _ := tar.Hashes().Best(); algo != apt.HashSHA1 {
		t.Errorf("tar Best() = %s", algo)
	}
}

func TestParseSourceRawsIgnoresMalformedChecksumLines(t *testing.T) {
	in := "Package: a\nVersion: 1\nDirectory: d\nChecksums-Sha256:\n onlytwo fields\n s2 5 ok.dsc\n\n"
	srcs, err := apt.ParseSourceRaws(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs[0].Files) != 1 || srcs[0].Files[0].Filename != "ok.dsc" {
		t.Fatalf("files = %+v", srcs[0].Files)
	}
}

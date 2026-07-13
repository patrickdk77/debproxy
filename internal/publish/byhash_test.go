package publish_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/publish"
)

func TestGenerateSuite_AcquireByHashDeclared(t *testing.T) {
	files := generate(t, publish.Compression{GZip: 6})
	release, ok := files["root/dists/trixie/Release"]
	if !ok {
		t.Fatal("Release not written")
	}
	if !strings.Contains(string(release), "Acquire-By-Hash: yes") {
		t.Fatalf("expected Release to declare Acquire-By-Hash: yes, got:\n%s", release)
	}
}

func TestGenerateSuite_ByHashSiblingWritten(t *testing.T) {
	files := generate(t, publish.Compression{GZip: 6})
	plain, ok := files[relGz]
	if !ok {
		t.Fatal("Packages.gz not written")
	}
	sum := sha256.Sum256(plain)
	wantPath := "root/dists/trixie/main/binary-amd64/by-hash/SHA256/" + hex.EncodeToString(sum[:])

	byHash, ok := files[wantPath]
	if !ok {
		t.Fatalf("expected by-hash sibling at %s, got files: %v", wantPath, keysOf(files))
	}
	if string(byHash) != string(plain) {
		t.Fatal("by-hash sibling content does not match the plain-named file's content")
	}
}

func TestGenerateSuite_SkipByHashSuppressesSiblingWrites(t *testing.T) {
	sink := newFakeSink()
	in := publish.SuiteInput{
		OS:            "debian",
		Codename:      "trixie",
		Architectures: []string{"amd64"},
		Components:    []string{"main"},
		Stanzas: map[string]map[string][]string{
			"main": {"amd64": {testStanza}},
		},
		Compression: publish.Compression{GZip: 6},
		SkipByHash:  true,
	}
	if err := publish.GenerateSuite(context.Background(), sink, "root", in, nil); err != nil {
		t.Fatalf("GenerateSuite: %v", err)
	}

	if _, ok := sink.files[relGz]; !ok {
		t.Fatal("Packages.gz should still be written even with SkipByHash")
	}
	for key := range sink.files {
		if strings.Contains(key, "/by-hash/") {
			t.Errorf("expected no by-hash sibling with SkipByHash: true, got %q", key)
		}
	}

	// Release should still declare Acquire-By-Hash and still list the
	// plain-named file's hash -- SkipByHash only suppresses the sibling
	// file, not the hash a client would derive a by-hash path from.
	release := string(sink.files["root/dists/trixie/Release"])
	if !strings.Contains(release, "Acquire-By-Hash: yes") {
		t.Fatal("expected Acquire-By-Hash: yes even with SkipByHash")
	}
	if !strings.Contains(release, "Packages.gz") {
		t.Fatal("expected Release to still list the plain-named file's hash")
	}
}

func TestGenerateSuite_SourcesByHashSiblingWritten(t *testing.T) {
	sink := newFakeSink()
	in := publish.SuiteInput{
		OS:            "debian",
		Codename:      "trixie",
		Architectures: []string{"amd64"},
		Components:    []string{"main"},
		Stanzas: map[string]map[string][]string{
			"main": {"amd64": {testStanza}},
		},
		SourceStanzas: map[string][]string{
			"main": {"Package: hello\nVersion: 1.0\n\n"},
		},
		Compression: publish.Compression{GZip: 6},
	}
	if err := publish.GenerateSuite(context.Background(), sink, "root", in, nil); err != nil {
		t.Fatalf("GenerateSuite: %v", err)
	}

	const relSourcesGz = "root/dists/trixie/main/source/Sources.gz"
	plain, ok := sink.files[relSourcesGz]
	if !ok {
		t.Fatal("Sources.gz not written")
	}
	sum := sha256.Sum256(plain)
	wantPath := "root/dists/trixie/main/source/by-hash/SHA256/" + hex.EncodeToString(sum[:])
	byHash, ok := sink.files[wantPath]
	if !ok {
		t.Fatalf("expected by-hash sibling at %s, got files: %v", wantPath, keysOf(sink.files))
	}
	if string(byHash) != string(plain) {
		t.Fatal("by-hash sibling content does not match Sources.gz's content")
	}
}

func TestGenerateSuite_ByHashPathsNotListedInReleaseHashSection(t *testing.T) {
	files := generate(t, publish.Compression{GZip: 6})
	release := string(files["root/dists/trixie/Release"])
	if strings.Contains(release, "by-hash") {
		t.Fatalf("Release must not list by-hash paths itself (a client derives them from the plain entry's hash), got:\n%s", release)
	}
}

func TestGenerateSuite_ByHashUsesSHA256EvenWhenHashTypesExcludesIt(t *testing.T) {
	sink := newFakeSink()
	in := publish.SuiteInput{
		OS:            "debian",
		Codename:      "trixie",
		Architectures: []string{"amd64"},
		Components:    []string{"main"},
		Stanzas: map[string]map[string][]string{
			"main": {"amd64": {testStanza}},
		},
		Compression: publish.Compression{GZip: 6},
		HashTypes:   []string{"md5sum"}, // deliberately excludes sha256
	}
	if err := publish.GenerateSuite(context.Background(), sink, "root", in, nil); err != nil {
		t.Fatalf("GenerateSuite: %v", err)
	}

	plain, ok := sink.files[relGz]
	if !ok {
		t.Fatal("Packages.gz not written")
	}
	sum := sha256.Sum256(plain)
	wantPath := "root/dists/trixie/main/binary-amd64/by-hash/SHA256/" + hex.EncodeToString(sum[:])
	if _, ok := sink.files[wantPath]; !ok {
		t.Fatalf("expected by-hash sibling to be populated even though hash_types excludes sha256, got files: %v", keysOf(sink.files))
	}

	// The Release text itself should still respect the configured
	// hash_types -- no SHA256: section, since that was explicitly excluded.
	release := string(sink.files["root/dists/trixie/Release"])
	if strings.Contains(release, "SHA256:") {
		t.Fatalf("expected no SHA256 section in Release when hash_types excludes it, got:\n%s", release)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

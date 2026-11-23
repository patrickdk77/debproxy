package upstream_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/debproxy/debproxy/internal/upstream"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/klauspost/compress/gzip"
)

func hexSum(algo string, data []byte) string {
	switch algo {
	case "MD5Sum":
		s := md5.Sum(data)
		return hex.EncodeToString(s[:])
	case "SHA1":
		s := sha1.Sum(data)
		return hex.EncodeToString(s[:])
	case "SHA256":
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	case "SHA512":
		s := sha512.Sum512(data)
		return hex.EncodeToString(s[:])
	}
	panic(algo)
}

// hashedUpstream serves one package behind a Release whose hash sections
// are exactly the ones listed in sections. wrong names a section whose
// digests are deliberately corrupted. byHash adds Acquire-By-Hash and
// serves the index under every by-hash directory for the listed sections.
type hashedUpstream struct {
	url   string
	mu    sync.Mutex
	paths []string
}

func (h *hashedUpstream) requested(prefix string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.paths {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func buildHashedUpstream(t *testing.T, key *signing.Key, sections []string, wrong string, byHash bool) *hashedUpstream {
	t.Helper()
	deb := []byte("fake .deb binary content for hash preference tests")
	debPath := "pool/main/h/hello/hello_1.0_amd64.deb"
	control := apt.NewParagraph()
	control.Set("Package", "hello")
	control.Set("Version", "1.0")
	control.Set("Architecture", "amd64")
	control.Set("Section", "utils")
	control.Set("Maintainer", "T <t@example.com>")
	control.Set("Description", "hello")
	stanza := apt.BuildPackagesStanza(control, debPath, int64(len(deb)), hexSum("SHA256", deb), "")
	var pkgBuf bytes.Buffer
	if err := apt.WriteParagraphs(&pkgBuf, []*apt.Paragraph{stanza}); err != nil {
		t.Fatal(err)
	}
	packages := pkgBuf.Bytes()
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(packages); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	packagesGZ := gzBuf.Bytes()

	var rel strings.Builder
	rel.WriteString("Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\n")
	if byHash {
		rel.WriteString("Acquire-By-Hash: yes\n")
	}
	digests := map[string]map[string]string{}
	for _, sec := range sections {
		plain, gzd := hexSum(sec, packages), hexSum(sec, packagesGZ)
		if sec == wrong {
			plain = strings.Repeat("0", len(plain))
			gzd = strings.Repeat("0", len(gzd))
		}
		digests[sec] = map[string]string{"Packages": plain, "Packages.gz": gzd}
		fmt.Fprintf(&rel, "%s:\n %s %d main/binary-amd64/Packages\n %s %d main/binary-amd64/Packages.gz\n",
			sec, plain, len(packages), gzd, len(packagesGZ))
	}
	inRelease, err := key.SignInline([]byte(rel.String()))
	if err != nil {
		t.Fatal(err)
	}

	h := &hashedUpstream{}
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(packagesGZ)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(packages)
	})
	if byHash {
		for sec, d := range digests {
			mux.HandleFunc("/dists/trixie/main/binary-amd64/by-hash/"+sec+"/"+d["Packages.gz"], func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(packagesGZ)
			})
		}
	}
	mux.HandleFunc("/"+debPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(deb)
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.paths = append(h.paths, r.URL.Path)
		h.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	h.url = srv.URL
	return h
}

func fetchHello(t *testing.T, u *hashedUpstream, keyring openpgp.EntityList) (int, error) {
	t.Helper()
	src := makeSource(t, u.url, keyring)
	f := upstream.NewFetcher(src, nil)
	idx, err := f.FetchIndex(context.Background())
	if err != nil {
		return 0, err
	}
	return len(idx.ByArch["amd64"]), nil
}

// The strongest hash the Release lists is the one that verifies the index.
// A Release listing only SHA512 used to fail outright: the fetcher only
// ever read SHA256 and treated its absence as a mismatch.
func TestFetchIndexVerifiesWithSHA512Only(t *testing.T) {
	key, keyring := testKey(t)
	u := buildHashedUpstream(t, key, []string{"SHA512"}, "", false)
	n, err := fetchHello(t, u, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("got %d packages from a SHA512-only Release, want 1", n)
	}
}

// With nothing stronger listed, SHA1 or MD5Sum is what there is.
func TestFetchIndexFallsBackToWeakHashesWhenAlone(t *testing.T) {
	for _, sec := range []string{"SHA1", "MD5Sum"} {
		t.Run(sec, func(t *testing.T) {
			key, keyring := testKey(t)
			u := buildHashedUpstream(t, key, []string{sec}, "", false)
			n, err := fetchHello(t, u, keyring)
			if err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Fatalf("got %d packages from a %s-only Release, want 1", n, sec)
			}
		})
	}
}

// A weak hash that matches must not rescue a strong one that does not.
func TestFetchIndexStrongMismatchIsNotRescuedByWeakMatch(t *testing.T) {
	key, keyring := testKey(t)
	u := buildHashedUpstream(t, key, []string{"MD5Sum", "SHA1", "SHA256"}, "SHA256", false)
	n, err := fetchHello(t, u, keyring)
	if err == nil && n != 0 {
		t.Fatalf("index with a wrong SHA256 was accepted on the strength of its MD5Sum and SHA1 (%d packages)", n)
	}
}

// Stronger beats weaker in the other direction too: a wrong SHA1 beside
// a right SHA256 is irrelevant, because SHA1 is never consulted then.
func TestFetchIndexIgnoresWeakHashWhenStrongPresent(t *testing.T) {
	key, keyring := testKey(t)
	u := buildHashedUpstream(t, key, []string{"SHA1", "SHA256"}, "SHA1", false)
	n, err := fetchHello(t, u, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("got %d packages, want 1 (wrong SHA1 next to a right SHA256)", n)
	}
}

// by-hash addresses the index by the same strongest hash.
func TestFetchIndexByHashUsesStrongestListedHash(t *testing.T) {
	key, keyring := testKey(t)
	u := buildHashedUpstream(t, key, []string{"MD5Sum", "SHA256", "SHA512"}, "", true)
	n, err := fetchHello(t, u, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("got %d packages, want 1", n)
	}
	if !u.requested("/dists/trixie/main/binary-amd64/by-hash/SHA512/") {
		t.Fatalf("index was not fetched via by-hash/SHA512; paths: %v", u.paths)
	}
	if u.requested("/dists/trixie/main/binary-amd64/by-hash/SHA256/") || u.requested("/dists/trixie/main/binary-amd64/by-hash/MD5Sum/") {
		t.Fatalf("a weaker by-hash directory was used although SHA512 is listed; paths: %v", u.paths)
	}
}

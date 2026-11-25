package upstream_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/upstream"
)

// buildFilterUpstream serves a suite with two binary packages, hello and
// evil-hello, and a Sources index naming the same two source packages.
func buildFilterUpstream(t *testing.T, key *signing.Key) string {
	t.Helper()

	var pkgBuf bytes.Buffer
	var stanzas []*apt.Paragraph
	for _, name := range []string{"hello", "evil-hello"} {
		content := []byte("deb content of " + name)
		sum := sha256.Sum256(content)
		control := apt.NewParagraph()
		control.Set("Package", name)
		control.Set("Version", "1.0")
		control.Set("Architecture", "amd64")
		control.Set("Section", "utils")
		control.Set("Maintainer", "T <t@example.com>")
		control.Set("Description", name)
		path := fmt.Sprintf("pool/main/%s/%s/%s_1.0_amd64.deb", name[:1], name, name)
		stanzas = append(stanzas, apt.BuildPackagesStanza(control, path, int64(len(content)), hex.EncodeToString(sum[:]), ""))
	}
	if err := apt.WriteParagraphs(&pkgBuf, stanzas); err != nil {
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
	sources := []byte("Package: hello\nVersion: 1.0\nDirectory: pool/main/h/hello\n\nPackage: evil-hello\nVersion: 1.0\nDirectory: pool/main/e/evil-hello\n")

	plainSum := sha256.Sum256(packages)
	gzSum := sha256.Sum256(packagesGZ)
	srcSum := sha256.Sum256(sources)
	release := []byte(fmt.Sprintf(
		"Origin: Test\nCodename: trixie\nSuite: trixie\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages\n %s %d main/binary-amd64/Packages.gz\n %s %d main/source/Sources\n",
		hex.EncodeToString(plainSum[:]), len(packages),
		hex.EncodeToString(gzSum[:]), len(packagesGZ),
		hex.EncodeToString(srcSum[:]), len(sources),
	))
	inRelease, err := key.SignInline(release)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/trixie/InRelease", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(inRelease)
	})
	mux.HandleFunc("/dists/trixie/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(packagesGZ)
	})
	mux.HandleFunc("/dists/trixie/main/source/Sources", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sources)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func filteredSource(t *testing.T, srvURL string, keyring openpgp.EntityList, allow, deny string) model.UpstreamSource {
	t.Helper()
	src := makeSource(t, srvURL, keyring)
	src.FetchSources = true
	if allow == "" && deny == "" {
		return src
	}
	src.Filter = &model.PackageFilter{}
	if allow != "" {
		src.Filter.Allow = regexp.MustCompile(allow)
	}
	if deny != "" {
		src.Filter.Deny = regexp.MustCompile(deny)
	}
	return src
}

func indexNames(t *testing.T, f *upstream.Fetcher) []string {
	t.Helper()
	idx, err := f.FetchIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range idx.ByArch["amd64"] {
		names = append(names, p.Package)
	}
	sort.Strings(names)
	return names
}

func sourceNames(t *testing.T, f *upstream.Fetcher) []string {
	t.Helper()
	srcs, err := f.FetchSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range srcs {
		names = append(names, s.Package)
	}
	sort.Strings(names)
	return names
}

func TestFetchIndexPackageFilter(t *testing.T) {
	key, keyring := testKey(t)
	srvURL := buildFilterUpstream(t, key)

	cases := []struct {
		name        string
		allow, deny string
		want        string
	}{
		{"no filter keeps every package", "", "", "[evil-hello hello]"},
		{"deny drops a match", "", "evil", "[hello]"},
		{"allow keeps only matches", "^evil", "", "[evil-hello]"},
		{"allow and deny both apply", "hello", "evil", "[hello]"},
		{"allow nothing matches", "^nothing$", "", "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := upstream.NewFetcher(filteredSource(t, srvURL, keyring, tc.allow, tc.deny), nil)
			if got := fmt.Sprint(indexNames(t, f)); got != tc.want {
				t.Fatalf("packages = %s, want %s", got, tc.want)
			}
			if got := fmt.Sprint(sourceNames(t, f)); got != tc.want {
				t.Fatalf("sources = %s, want %s", got, tc.want)
			}
		})
	}
}

// A filtered fetcher and an unfiltered one share one IndexCache entry, so
// the filter must apply on the cached path too and must not strip packages
// out of the shared entry.
func TestFetchIndexPackageFilterOnCachedIndex(t *testing.T) {
	key, keyring := testKey(t)
	srvURL := buildFilterUpstream(t, key)
	cache := upstream.NewIndexCache()

	filtered := upstream.NewFetcherWithCache(filteredSource(t, srvURL, keyring, "", "evil"), nil, cache)
	for i := 0; i < 2; i++ {
		if got := fmt.Sprint(indexNames(t, filtered)); got != "[hello]" {
			t.Fatalf("fetch %d: packages = %s, want [hello]", i+1, got)
		}
		if got := fmt.Sprint(sourceNames(t, filtered)); got != "[hello]" {
			t.Fatalf("fetch %d: sources = %s, want [hello]", i+1, got)
		}
	}

	plain := upstream.NewFetcherWithCache(filteredSource(t, srvURL, keyring, "", ""), nil, cache)
	if got := fmt.Sprint(indexNames(t, plain)); got != "[evil-hello hello]" {
		t.Fatalf("unfiltered fetcher on the shared cache: packages = %s, want [evil-hello hello]", got)
	}
	if got := fmt.Sprint(sourceNames(t, plain)); got != "[evil-hello hello]" {
		t.Fatalf("unfiltered fetcher on the shared cache: sources = %s, want [evil-hello hello]", got)
	}
}

// AdoptFromValkeyOutright and AdoptSourcesFromValkeyOutright hand out the
// cached entry without a fetch; avail.Build and pool resolution use them
// whenever the layout is fresh, so the filter must apply there too.
func TestFetchIndexPackageFilterOnAdoptedIndex(t *testing.T) {
	key, keyring := testKey(t)
	srvURL := buildFilterUpstream(t, key)
	cache := upstream.NewIndexCache()

	plain := upstream.NewFetcherWithCache(filteredSource(t, srvURL, keyring, "", ""), nil, cache)
	indexNames(t, plain)
	sourceNames(t, plain)

	filtered := upstream.NewFetcherWithCache(filteredSource(t, srvURL, keyring, "", "evil"), nil, cache)
	idx, ok := filtered.AdoptFromValkeyOutright(context.Background())
	if !ok {
		t.Fatal("nothing adopted from the shared cache")
	}
	var names []string
	for _, p := range idx.ByArch["amd64"] {
		names = append(names, p.Package)
	}
	if got := fmt.Sprint(names); got != "[hello]" {
		t.Fatalf("adopted packages = %s, want [hello]", got)
	}
	srcs, ok := filtered.AdoptSourcesFromValkeyOutright(context.Background())
	if !ok {
		t.Fatal("no sources adopted from the shared cache")
	}
	names = nil
	for _, s := range srcs {
		names = append(names, s.Package)
	}
	if got := fmt.Sprint(names); got != "[hello]" {
		t.Fatalf("adopted sources = %s, want [hello]", got)
	}
	if got := fmt.Sprint(indexNames(t, plain)); got != "[evil-hello hello]" {
		t.Fatalf("shared entry was filtered in place: packages = %s", got)
	}
}

// The filter belongs to the upstream, not to its scheme: an s3 upstream
// with a packages map is filtered like an http one.
func TestFetchIndexPackageFilterOverS3(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	fake := newFakeS3(t, "apt", buildFilterUpstream(t, key), secrets)
	src := s3Source(t, fake, "apt", keyring)
	src.FetchSources = true
	src.Filter = &model.PackageFilter{Deny: regexp.MustCompile("evil")}
	f := upstream.NewFetcher(src, upstream.NewHTTPClient("", ""))
	if got := fmt.Sprint(indexNames(t, f)); got != "[hello]" {
		t.Fatalf("packages over s3 = %s, want [hello]", got)
	}
	if got := fmt.Sprint(sourceNames(t, f)); got != "[hello]" {
		t.Fatalf("sources over s3 = %s, want [hello]", got)
	}
}

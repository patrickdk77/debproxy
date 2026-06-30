package server_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/klauspost/compress/gzip"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/server"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storagefactory"
	"github.com/debproxy/debproxy/internal/syncer"
)

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Upstream and repository signing keys.
	upstreamPriv := filepath.Join(dir, "upstream.priv.asc")
	upstreamPub := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, upstreamPriv, upstreamPub)
	repoPriv := filepath.Join(dir, "repo.priv.asc")
	writeKeyPair(t, repoPriv, "")

	upstreamKey, err := signing.Load(upstreamPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Build a .deb and the fake upstream repository tree.
	helloControl := "Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: hello\n"
	helloDeb := buildDeb(t, helloControl)
	helloUpstreamPath := "pool/main/h/hello/hello_1.0_amd64.deb"

	files := map[string][]byte{
		"/" + helloUpstreamPath: helloDeb,
	}
	packagesContent := packagesStanza(t, helloControl, helloUpstreamPath, helloDeb)
	packagesGz := gzipBytes(t, packagesContent)
	files["/dists/trixie/main/binary-amd64/Packages"] = packagesContent
	files["/dists/trixie/main/binary-amd64/Packages.gz"] = packagesGz

	release := buildUpstreamRelease(packagesContent, packagesGz)
	inRelease, err := upstreamKey.SignInline([]byte(release))
	if err != nil {
		t.Fatal(err)
	}
	files["/dists/trixie/InRelease"] = inRelease

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	// Write config pointing at the fake upstream.
	cfgPath := filepath.Join(dir, "config.yaml")
	writeConfig(t, cfgPath, dir, upstream.URL, upstreamPub, repoPriv)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storagefactory.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb822store.New(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := signing.Load(repoPriv)
	if err != nil {
		t.Fatal(err)
	}
	repoKeyring, err := repoKey.PublicKeyring()
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(server.New(cfg, store, index, repoKey, nil, nil, nil).Handler())
	defer srv.Close()

	// --- /live: verify signed Release, list package, pull-through the .deb ---
	liveBody := httpGet(t, srv.URL+"/live/debian/dists/trixie/InRelease")
	liveRelease, _, err := signing.VerifyClearsigned(liveBody, repoKeyring)
	if err != nil {
		t.Fatalf("verify /live InRelease: %v", err)
	}
	rel, err := apt.ParseRelease(bytes.NewReader(liveRelease))
	if err != nil {
		t.Fatal(err)
	}

	gzData := httpGet(t, srv.URL+"/live/debian/dists/trixie/main/binary-amd64/Packages.gz")
	entry, ok := rel.Files["main/binary-amd64/Packages.gz"]
	if !ok {
		t.Fatal("Release missing Packages.gz entry")
	}
	if sha256hex(gzData) != entry.SHA256 {
		t.Fatalf("/live Packages.gz hash mismatch: %s vs %s", sha256hex(gzData), entry.SHA256)
	}

	poolPath := firstFilename(t, gunzip(t, gzData))
	if !strings.Contains(poolPath, "hello_1.0_amd64.deb") {
		t.Fatalf("unexpected pool path %q", poolPath)
	}

	got := httpGet(t, srv.URL+"/live/debian/"+poolPath)
	if sha256hex(got) != sha256hex(helloDeb) {
		t.Fatal("/live pull-through returned wrong bytes")
	}

	// --- snapshot: publish cache state, verify /current serves it ---
	sy := syncer.New(cfg, store, index, repoKey, nil, nil, nil)
	if err := sy.Snapshot(context.Background(), time.Now()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	curBody := httpGet(t, srv.URL+"/current/debian/dists/trixie/InRelease")
	curRelease, _, err := signing.VerifyClearsigned(curBody, repoKeyring)
	if err != nil {
		t.Fatalf("verify /current InRelease: %v", err)
	}
	curRel, err := apt.ParseRelease(bytes.NewReader(curRelease))
	if err != nil {
		t.Fatal(err)
	}
	curGz := httpGet(t, srv.URL+"/current/debian/dists/trixie/main/binary-amd64/Packages.gz")
	if sha256hex(curGz) != curRel.Files["main/binary-amd64/Packages.gz"].SHA256 {
		t.Fatal("/current Packages.gz hash mismatch")
	}
	curPool := firstFilename(t, gunzip(t, curGz))
	curDeb := httpGet(t, srv.URL+"/current/debian/"+curPool)
	if sha256hex(curDeb) != sha256hex(helloDeb) {
		t.Fatal("/current served wrong .deb")
	}

	// --- conditional requests: ETag/If-None-Match -> 304 ---
	relURL := srv.URL + "/current/debian/dists/trixie/main/binary-amd64/Packages"
	resp, err := http.Get(relURL)
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	_ = resp.Body.Close()
	if etag == "" {
		t.Fatal("expected ETag on Packages response")
	}
	req, _ := http.NewRequest(http.MethodGet, relURL, nil)
	req.Header.Set("If-None-Match", etag)
	// Disable transparent decompression negotiation for a clean 304 check.
	req.Header.Set("Accept-Encoding", "identity")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified, got %d", resp2.StatusCode)
	}

	// --- compression negotiation on text Packages ---
	req3, _ := http.NewRequest(http.MethodGet, relURL, nil)
	req3.Header.Set("Accept-Encoding", "gzip")
	tr := &http.Transport{DisableCompression: true}
	resp3, err := (&http.Client{Transport: tr}).Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	enc := resp3.Header.Get("Content-Encoding")
	body3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if enc != "gzip" {
		t.Fatalf("expected gzip Content-Encoding, got %q", enc)
	}
	if string(gunzip(t, body3)) == "" {
		t.Fatal("expected non-empty gzip body")
	}
}

func TestUpdateJob(t *testing.T) {
	dir := t.TempDir()

	upstreamPriv := filepath.Join(dir, "upstream.priv.asc")
	upstreamPub := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, upstreamPriv, upstreamPub)
	repoPriv := filepath.Join(dir, "repo.priv.asc")
	writeKeyPair(t, repoPriv, "")
	upstreamKey, err := signing.Load(upstreamPriv)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	files := map[string][]byte{}

	setVersion := func(version string) {
		control := fmt.Sprintf("Package: hello\nVersion: %s\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: hello\n", version)
		deb := buildDeb(t, control)
		upstreamPath := fmt.Sprintf("pool/main/h/hello/hello_%s_amd64.deb", version)
		packages := packagesStanza(t, control, upstreamPath, deb)
		gz := gzipBytes(t, packages)
		release := buildUpstreamRelease(packages, gz)
		inRelease, err := upstreamKey.SignInline([]byte(release))
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		files["/"+upstreamPath] = deb
		files["/dists/trixie/main/binary-amd64/Packages"] = packages
		files["/dists/trixie/main/binary-amd64/Packages.gz"] = gz
		files["/dists/trixie/InRelease"] = inRelease
	}
	setVersion("1.0")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		data, ok := files[r.URL.Path]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	defer upstream.Close()

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`storage:
  backend: filesystem
  filesystem:
    root: %s
upstreams:
  debian-security:
    url: %s
    suite: "{codename}"
    keys: [%s]
    auto_update: true
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-security]
signing:
  private_key: %s
`, filepath.Join(dir, "store"), upstream.URL, upstreamPub, repoPriv)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storagefactory.New(loaded)
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb822store.New(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := signing.Load(repoPriv)
	if err != nil {
		t.Fatal(err)
	}
	repoKeyring, err := repoKey.PublicKeyring()
	if err != nil {
		t.Fatal(err)
	}

	sy := syncer.New(loaded, store, index, repoKey, nil, nil, nil)
	if err := sy.Prime(context.Background(), "debian", "trixie", "main", []string{"hello"}); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// New upstream version becomes available; the update job should pull it.
	setVersion("2.0")
	if err := sy.Update(context.Background()); err != nil {
		t.Fatalf("update: %v", err)
	}

	srv := httptest.NewServer(server.New(loaded, store, index, repoKey, nil, nil, nil).Handler())
	defer srv.Close()

	body := httpGet(t, srv.URL+"/current/debian/dists/trixie/InRelease")
	if _, _, err := signing.VerifyClearsigned(body, repoKeyring); err != nil {
		t.Fatalf("verify InRelease: %v", err)
	}
	gz := httpGet(t, srv.URL+"/current/debian/dists/trixie/main/binary-amd64/Packages.gz")
	paras, err := apt.ParseParagraphs(bytes.NewReader(gunzip(t, gz)))
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]bool{}
	for _, p := range paras {
		versions[p.Get("Version")] = true
	}
	if !versions["2.0"] {
		t.Fatalf("expected hello 2.0 after update, got versions %v", versions)
	}
}

func httpGet(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func firstFilename(t *testing.T, packages []byte) string {
	t.Helper()
	paras, err := apt.ParseParagraphs(bytes.NewReader(packages))
	if err != nil {
		t.Fatal(err)
	}
	if len(paras) == 0 {
		t.Fatal("no packages in index")
	}
	return paras[0].Get("Filename")
}

func packagesStanza(t *testing.T, control, filename string, deb []byte) []byte {
	t.Helper()
	para, err := apt.ParseStanza(control)
	if err != nil {
		t.Fatal(err)
	}
	stanza := apt.BuildPackagesStanza(para, filename, int64(len(deb)), sha256hex(deb), "")
	s, err := apt.StanzaString(stanza)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s + "\n")
}

func buildUpstreamRelease(packages, packagesGz []byte) string {
	var sb strings.Builder
	sb.WriteString("Origin: Test\nLabel: Test\nSuite: trixie\nCodename: trixie\n")
	sb.WriteString("Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC") + "\n")
	sb.WriteString("Architectures: amd64\nComponents: main\n")
	sb.WriteString("SHA256:\n")
	sb.WriteString(fmt.Sprintf(" %s %s main/binary-amd64/Packages\n", sha256hex(packages), strconv.Itoa(len(packages))))
	sb.WriteString(fmt.Sprintf(" %s %s main/binary-amd64/Packages.gz\n", sha256hex(packagesGz), strconv.Itoa(len(packagesGz))))
	return sb.String()
}

func writeConfig(t *testing.T, path, root, upstreamURL, upstreamPub, repoPriv string) {
	t.Helper()
	cfg := fmt.Sprintf(`storage:
  backend: filesystem
  filesystem:
    root: %s
upstreams:
  debian-main:
    url: %s
    keys: [%s]
    auto_update: false
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-main]
signing:
  private_key: %s
`, filepath.Join(root, "store"), upstreamURL, upstreamPub, repoPriv)
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeKeyPair(t *testing.T, privPath, pubPath string) {
	t.Helper()
	entity, err := openpgp.NewEntity("debproxy-test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	privFile, err := os.Create(privPath)
	if err != nil {
		t.Fatal(err)
	}
	defer privFile.Close()
	pw, err := armor.Encode(privFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(pw, nil); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}

	if pubPath == "" {
		return
	}
	pubFile, err := os.Create(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	defer pubFile.Close()
	aw, err := armor.Encode(pubFile, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(aw); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
}

// buildDeb constructs a minimal ar(5) .deb with debian-binary, control.tar.gz,
// and an empty data.tar.gz.
func buildDeb(t *testing.T, control string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")

	writeMember := func(name string, data []byte) {
		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data))
		buf.WriteString(header)
		buf.Write(data)
		if len(data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}

	writeMember("debian-binary", []byte("2.0\n"))

	controlTar := gzipBytes(t, tarSingleFile(t, "./control", []byte(control)))
	writeMember("control.tar.gz", controlTar)

	dataTar := gzipBytes(t, tarEmpty(t))
	writeMember("data.tar.gz", dataTar)

	return buf.Bytes()
}

func tarSingleFile(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarEmpty(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gunzip(t *testing.T, data []byte) []byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	out, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

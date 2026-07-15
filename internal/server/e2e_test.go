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
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/server"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storagefactory"
	"github.com/debproxy/debproxy/internal/syncer"
	"github.com/debproxy/debproxy/internal/webhook"
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

	srv := httptest.NewServer(server.New(cfg, store, index, repoKey, nil, nil, nil, nil).Handler())
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
	if err := sy.Snapshot(context.Background(), time.Now()); err != nil {
		t.Fatalf("snapshot after update: %v", err)
	}

	srv := httptest.NewServer(server.New(loaded, store, index, repoKey, nil, nil, nil, nil).Handler())
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

// TestUpdateJobWebhookOnlyFiresForTopLevelPackageNotDependencies is the direct
// regression test for the auto_update webhook fix: hello (auto_update: true)
// Depends on libhello, served by a separate upstream with auto_update: false.
// When hello's newer version pulls in a newer libhello too (to satisfy that
// Depends), only hello -- the package whose version bump actually triggered
// the update -- should fire a webhook. libhello's download must still happen
// (its own newer version is a real dependency requirement), but silently: it
// isn't a separate update of its own, just part of satisfying hello's.
func TestUpdateJobWebhookOnlyFiresForTopLevelPackageNotDependencies(t *testing.T) {
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

	// newUpstream stands up one single-package upstream archive (its own
	// dists/trixie/InRelease etc.), independent of any other so each package
	// can be given its own auto_update setting in the config below.
	newUpstream := func(pkgName, extraControl string) (srv *httptest.Server, setVersion func(string)) {
		var mu sync.Mutex
		files := map[string][]byte{}
		set := func(version string) {
			control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: %s\n%s",
				pkgName, version, pkgName, extraControl)
			deb := buildDeb(t, control)
			upstreamPath := fmt.Sprintf("pool/main/%s/%s_%s_amd64.deb", pkgName, pkgName, version)
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
		set("1.0")
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			data, ok := files[r.URL.Path]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		}))
		return s, set
	}

	helloSrv, setHello := newUpstream("hello", "Depends: libhello\n")
	defer helloSrv.Close()
	libSrv, setLib := newUpstream("libhello", "")
	defer libSrv.Close()

	var hookMu sync.Mutex
	var received []string
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hookMu.Lock()
		received = append(received, string(body))
		hookMu.Unlock()
	}))
	defer hookSrv.Close()
	notifier, err := webhook.New([]webhook.Def{{URL: hookSrv.URL, Body: "{{.Package}} {{.Version}}"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`storage:
  backend: filesystem
  filesystem:
    root: %s
upstreams:
  hello-src:
    url: %s
    suite: "{codename}"
    keys: [%s]
    auto_update: true
  lib-src:
    url: %s
    suite: "{codename}"
    keys: [%s]
    auto_update: false
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [hello-src, lib-src]
signing:
  private_key: %s
`, filepath.Join(dir, "store"), helloSrv.URL, upstreamPub, libSrv.URL, upstreamPub, repoPriv)
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

	// waitForHooks blocks until at least want events have landed (Notifier.Fire
	// dispatches each hook in its own goroutine, so arrival isn't synchronous
	// with the Cache call that triggered it), then a short grace period to
	// catch any further, unwanted arrivals, and returns everything received.
	waitForHooks := func(want int) []string {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			hookMu.Lock()
			n := len(received)
			hookMu.Unlock()
			if n >= want || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond) // grace period for stragglers
		hookMu.Lock()
		defer hookMu.Unlock()
		return append([]string(nil), received...)
	}

	sy := syncer.New(loaded, store, index, repoKey, nil, nil, notifier)
	if err := sy.Prime(context.Background(), "debian", "trixie", "main", []string{"hello"}); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if got := waitForHooks(2); len(got) != 2 {
		t.Fatalf("expected exactly 2 webhooks fired by Prime (hello and libhello), got %d: %v", len(got), got)
	}

	// Prime's own webhooks aren't what this test is about -- only Update's
	// behavior is.
	hookMu.Lock()
	received = nil
	hookMu.Unlock()

	setHello("2.0")
	setLib("2.0")
	if err := sy.Update(context.Background()); err != nil {
		t.Fatalf("update: %v", err)
	}

	got := waitForHooks(1)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 webhook fired by Update (hello only), got %d: %v", len(got), got)
	}
	if got[0] != "hello 2.0" {
		t.Errorf("webhook fired for %q, want \"hello 2.0\"", got[0])
	}

	if err := sy.Snapshot(context.Background(), time.Now()); err != nil {
		t.Fatalf("snapshot after update: %v", err)
	}
	srv := httptest.NewServer(server.New(loaded, store, index, repoKey, nil, nil, notifier, nil).Handler())
	defer srv.Close()
	gz := httpGet(t, srv.URL+"/current/debian/dists/trixie/main/binary-amd64/Packages.gz")
	paras, err := apt.ParseParagraphs(bytes.NewReader(gunzip(t, gz)))
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{}
	for _, p := range paras {
		versions[p.Get("Package")] = p.Get("Version")
	}
	if versions["hello"] != "2.0" {
		t.Errorf("hello version = %q, want 2.0", versions["hello"])
	}
	if versions["libhello"] != "2.0" {
		t.Errorf("libhello version = %q, want 2.0 (dependency must still be downloaded, just silently)", versions["libhello"])
	}
}

// TestLiveRejectsUnknownCombosWithoutRealWork proves the routing-layer fix:
// requests for an os/codename/upstream combination that doesn't match any
// configured layout are rejected with 404 before any real work is attempted
// -- no upstream contact, no live-index build -- rather than being allowed
// through and merely relabeled to a metrics sentinel afterward.
func TestLiveRejectsUnknownCombosWithoutRealWork(t *testing.T) {
	dir := t.TempDir()

	upstreamPub := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, filepath.Join(dir, "upstream.priv.asc"), upstreamPub)
	repoPriv := filepath.Join(dir, "repo.priv.asc")
	writeKeyPair(t, repoPriv, "")

	var upstreamHits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits = append(upstreamHits, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer upstream.Close()

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

	srv := httptest.NewServer(server.New(cfg, store, index, repoKey, nil, nil, nil, nil).Handler())
	defer srv.Close()

	// The config only knows os=debian, codename=trixie, upstream=debian-main.
	cases := []string{
		srv.URL + "/live/bogus-os/pool/trixie/debian-main/main/h/hello/hello_1.0_amd64.deb",
		srv.URL + "/live/debian/pool/bogus-codename/debian-main/main/h/hello/hello_1.0_amd64.deb",
		srv.URL + "/live/debian/pool/trixie/bogus-upstream/main/h/hello/hello_1.0_amd64.deb",
		srv.URL + "/live/debian/src/debian/bogus-codename/debian-main/main/h/hello/hello_1.0.orig.tar.gz",
		srv.URL + "/live/bogus-os/dists/trixie/main/binary-amd64/Packages",
		srv.URL + "/live/debian/dists/bogus-codename/main/binary-amd64/Packages",
	}
	for _, url := range cases {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status=%d, want 404", url, resp.StatusCode)
		}
	}

	if len(upstreamHits) != 0 {
		t.Errorf("expected zero upstream requests for unknown combinations, got %v", upstreamHits)
	}
}

// TestLiveSourcePullThrough exercises a full /live source (deb-src)
// pull-through: an upstream Sources index plus the actual .orig.tar.gz it
// references, requested through the same URL shape debproxy itself emits in
// the generated Sources index's Directory: field (which, like pool paths,
// embeds the OS a second time -- see model.SourceDir/model.PoolPath).
//
// An earlier investigation suspected this path always failed with a 502
// because pullThroughSource's parsing looks like it expects one more path
// segment than handleLive's "src" branch supplies. That reasoning used a
// hand-built URL missing the second (repeated) OS segment; with the correct,
// server-generated URL shape the segment counts line up and this passes,
// so that finding was a false positive from a wrong test URL, not a real bug.
func TestLiveSourcePullThrough(t *testing.T) {
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

	origTar := []byte("fake orig tarball contents")
	const upstreamDir = "pool/main/h/hello"
	const filename = "hello_1.0.orig.tar.gz"

	sourcesStanza := fmt.Sprintf(
		"Package: hello\nVersion: 1.0\nDirectory: %s\nChecksums-Sha256:\n %s %d %s\n\n",
		upstreamDir, sha256hex(origTar), len(origTar), filename)
	sourcesGz := gzipBytes(t, []byte(sourcesStanza))

	files := map[string][]byte{
		"/" + upstreamDir + "/" + filename:     origTar,
		"/dists/trixie/main/source/Sources":    []byte(sourcesStanza),
		"/dists/trixie/main/source/Sources.gz": sourcesGz,
	}

	var release strings.Builder
	release.WriteString("Origin: Test\nLabel: Test\nSuite: trixie\nCodename: trixie\n")
	release.WriteString("Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC") + "\n")
	release.WriteString("Architectures: amd64\nComponents: main\n")
	release.WriteString("SHA256:\n")
	fmt.Fprintf(&release, " %s %d main/source/Sources\n", sha256hex([]byte(sourcesStanza)), len(sourcesStanza))
	fmt.Fprintf(&release, " %s %d main/source/Sources.gz\n", sha256hex(sourcesGz), len(sourcesGz))
	inRelease, err := upstreamKey.SignInline([]byte(release.String()))
	if err != nil {
		t.Fatal(err)
	}
	files["/dists/trixie/InRelease"] = inRelease

	var upstreamHits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits = append(upstreamHits, r.URL.Path)
		if data, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	cfgPath := filepath.Join(dir, "config.yaml")
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
            sources: true
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

	srv := httptest.NewServer(server.New(loaded, store, index, repoKey, nil, nil, nil, nil).Handler())
	defer srv.Close()

	// Matches what debproxy itself would emit: Directory: src/debian/trixie/debian-main/main/h/hello
	url := srv.URL + "/live/debian/src/debian/trixie/debian-main/main/h/hello/" + filename
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s -> status=%d body=%q upstreamHits=%v", url, resp.StatusCode, body, upstreamHits)
	}
	if sha256hex(body) != sha256hex(origTar) {
		t.Fatalf("live source pull-through returned wrong bytes")
	}
}

// TestLiveSourcePullThroughScopesToRequestedUpstream is the regression test
// for pullThroughSource's Upstream-scoped FindSourceEntry fix: two upstreams
// (e.g. debian-main and debian-security) can each have their own persisted
// SourceEntry for a source package at the identical version, each pointing
// at its own upstream's base URL and Directory. Before FindSourceEntry was
// scoped by the upstream named in the request path, an unscoped "latest
// regardless of upstream" lookup could return either one, pairing the
// requested upstream's base URL with a *different* upstream's Directory --
// which 404s or 502s here because the two upstream mock servers each only
// serve their own file at their own path, never both.
func TestLiveSourcePullThroughScopesToRequestedUpstream(t *testing.T) {
	dir := t.TempDir()
	repoPriv := filepath.Join(dir, "repo.priv.asc")
	writeKeyPair(t, repoPriv, "")
	// Each upstream needs a configured key even though this test bypasses
	// real InRelease verification entirely (the metadata index is
	// pre-populated below) -- config validation requires at least one.
	upstreamPub := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, filepath.Join(dir, "upstream.priv.asc"), upstreamPub)

	const filename = "hello_1.0.orig.tar.gz"
	contentA := []byte("content from debian-main")
	contentB := []byte("content from debian-security")

	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pool/main/h/hello/"+filename {
			_, _ = w.Write(contentA)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pool/updates/main/h/hello/"+filename {
			_, _ = w.Write(contentB)
			return
		}
		http.NotFound(w, r)
	}))
	defer upstreamB.Close()

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`storage:
  backend: filesystem
  filesystem:
    root: %s
upstreams:
  debian-main:
    url: %s
    keys: [%s]
    auto_update: false
  debian-security:
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
            upstreams: [debian-main, debian-security]
            sources: true
signing:
  private_key: %s
`, filepath.Join(dir, "store"), upstreamA.URL, upstreamPub, upstreamB.URL, upstreamPub, repoPriv)
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

	// Pre-populate the metadata index as if an update job already ran
	// against both upstreams -- each upstream gets its own SourceEntry for
	// the identical "hello" 1.0, with its own UpstreamDir.
	ctx := context.Background()
	entryFor := func(upstream, upstreamDir string, content []byte) model.SourceEntry {
		sum := sha256.Sum256(content)
		return model.SourceEntry{
			OS: "debian", Codename: "trixie", Component: "main",
			Package: "hello", Version: "1.0", Upstream: upstream,
			LocalDir:    model.SourceDir("debian", "trixie", upstream, "main", "hello"),
			UpstreamDir: upstreamDir,
			Files: []model.SourceFile{{
				Filename: filename, Size: int64(len(content)), SHA256: model.Digest(hex.EncodeToString(sum[:])),
			}},
		}
	}
	if err := index.UpsertSourceEntry(ctx, entryFor("debian-main", "pool/main/h/hello", contentA)); err != nil {
		t.Fatal(err)
	}
	if err := index.UpsertSourceEntry(ctx, entryFor("debian-security", "pool/updates/main/h/hello", contentB)); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(server.New(loaded, store, index, repoKey, nil, nil, nil, nil).Handler())
	defer srv.Close()

	get := func(upstream string) (int, []byte) {
		url := srv.URL + "/live/debian/src/debian/trixie/" + upstream + "/main/h/hello/" + filename
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	statusA, bodyA := get("debian-main")
	if statusA != http.StatusOK {
		t.Fatalf("GET debian-main's own file -> status=%d body=%q", statusA, bodyA)
	}
	if string(bodyA) != string(contentA) {
		t.Fatalf("expected debian-main's own content, got %q", bodyA)
	}

	statusB, bodyB := get("debian-security")
	if statusB != http.StatusOK {
		t.Fatalf("GET debian-security's own file -> status=%d body=%q", statusB, bodyB)
	}
	if string(bodyB) != string(contentB) {
		t.Fatalf("expected debian-security's own content, got %q", bodyB)
	}
}

// setupHelloUpstream builds a signed InRelease/Packages/Packages.gz set for a
// single "hello" package and returns the .deb bytes plus a config-ready
// upstream base handler (InRelease/Packages/Packages.gz only -- the .deb path
// itself is deliberately left to each caller so it can control exactly how
// that one response behaves). Shared by the streaming pull-through tests
// below, which each need the same index but a different .deb response.
func setupHelloUpstream(t *testing.T) (deb []byte, upstreamPath string, baseHandler http.HandlerFunc, upstreamPub string) {
	t.Helper()
	dir := t.TempDir()
	upstreamPriv := filepath.Join(dir, "upstream.priv.asc")
	upstreamPubPath := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, upstreamPriv, upstreamPubPath)
	upstreamKey, err := signing.Load(upstreamPriv)
	if err != nil {
		t.Fatal(err)
	}

	control := "Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: hello\n"
	deb = buildDeb(t, control)
	upstreamPath = "pool/main/h/hello/hello_1.0_amd64.deb"
	packages := packagesStanza(t, control, upstreamPath, deb)
	gz := gzipBytes(t, packages)
	release := buildUpstreamRelease(packages, gz)
	inRelease, err := upstreamKey.SignInline([]byte(release))
	if err != nil {
		t.Fatal(err)
	}

	baseHandler = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/trixie/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/trixie/main/binary-amd64/Packages":
			_, _ = w.Write(packages)
		case "/dists/trixie/main/binary-amd64/Packages.gz":
			_, _ = w.Write(gz)
		default:
			http.NotFound(w, r)
		}
	}
	return deb, upstreamPath, baseHandler, upstreamPubPath
}

// newHelloServer writes the config wiring hello's upstream (at upstreamURL)
// into a single debian/trixie/main layout and returns a ready server plus
// its storage backend (for direct store.Exists assertions).
func newHelloServer(t *testing.T, upstreamURL, upstreamPub string) (*server.Server, storage.Storage) {
	t.Helper()
	dir := t.TempDir()
	repoPriv := filepath.Join(dir, "repo.priv.asc")
	writeKeyPair(t, repoPriv, "")

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`storage:
  backend: filesystem
  filesystem:
    root: %s
upstreams:
  debian-main:
    url: %s
    keys: [%s]
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
`, filepath.Join(dir, "store"), upstreamURL, upstreamPub, repoPriv)
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
	return server.New(loaded, store, index, repoKey, nil, nil, nil, nil), store
}

// TestPoolPullThroughFallsBackToUpstreamWhenLiveIndexMisses is the direct
// end-to-end regression test for the live-path fallback this session's
// ubuntu-security incident motivated: a package added upstream *after*
// debproxy already built and cached its live index for this layout (so the
// cached av genuinely doesn't have it yet -- no rebuild has happened since)
// must still be servable via pull-through, by checking the one upstream its
// pool path names directly (avail.ResolvePoolPath), rather than being
// rejected purely because this replica's last rebuild predates it.
func TestPoolPullThroughFallsBackToUpstreamWhenLiveIndexMisses(t *testing.T) {
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

	helloControl := "Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: hello\n"
	helloDeb := buildDeb(t, helloControl)
	const helloPath = "pool/main/h/hello/hello_1.0_amd64.deb"

	worldControl := "Package: world\nVersion: 1.0\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: world\n"
	worldDeb := buildDeb(t, worldControl)
	const worldPath = "pool/main/w/world/world_1.0_amd64.deb"

	// publish sets the upstream's current Packages listing to exactly the
	// given set of (control, path, deb) tuples -- called once with only
	// hello, then again after adding world, without debproxy ever being told
	// to refresh in between.
	publish := func(entries ...[3]any) {
		var packages bytes.Buffer
		mu.Lock()
		for _, e := range entries {
			control, path, deb := e[0].(string), e[1].(string), e[2].([]byte)
			packages.Write(packagesStanza(t, control, path, deb))
			files["/"+path] = deb
		}
		gz := gzipBytes(t, packages.Bytes())
		release := buildUpstreamRelease(packages.Bytes(), gz)
		inRelease, err := upstreamKey.SignInline([]byte(release))
		if err != nil {
			t.Fatal(err)
		}
		files["/dists/trixie/main/binary-amd64/Packages"] = packages.Bytes()
		files["/dists/trixie/main/binary-amd64/Packages.gz"] = gz
		files["/dists/trixie/InRelease"] = inRelease
		mu.Unlock()
	}
	publish([3]any{helloControl, helloPath, helloDeb}) // world doesn't exist yet

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
  debian-main:
    url: %s
    keys: [%s]
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

	srv := httptest.NewServer(server.New(loaded, store, index, repoKey, nil, nil, nil, nil).Handler())
	defer srv.Close()

	// Build and cache the live index while only hello exists upstream.
	helloResp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	helloResp.Body.Close()
	if helloResp.StatusCode != http.StatusOK {
		t.Fatalf("hello pull-through: status=%d", helloResp.StatusCode)
	}

	// Now world appears upstream -- debproxy is never told to refresh.
	publish([3]any{helloControl, helloPath, helloDeb}, [3]any{worldControl, worldPath, worldDeb})

	// world isn't in the live index debproxy already cached above, but the
	// pool path alone should be enough to resolve and fetch it directly.
	worldResp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/w/world/world_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer worldResp.Body.Close()
	body, _ := io.ReadAll(worldResp.Body)
	if worldResp.StatusCode != http.StatusOK {
		t.Fatalf("world pull-through: status=%d body=%q -- a package added upstream after the live index was built should still resolve via the direct-upstream fallback, not 502", worldResp.StatusCode, body)
	}
	if !bytes.Equal(body, worldDeb) {
		t.Fatal("world pull-through returned wrong bytes")
	}
}

// TestPoolPullThroughStreamsBeforeUpstreamFinishes is the direct regression
// test for the streaming pull-through fix: the client must receive bytes as
// they arrive from upstream, not only after the whole upstream response (and
// the subsequent write to storage) completes. The upstream handler sends
// half the .deb, flushes, and blocks -- if the client can read that first
// half before the handler is ever unblocked, debproxy is genuinely streaming
// rather than buffering.
func TestPoolPullThroughStreamsBeforeUpstreamFinishes(t *testing.T) {
	deb, upstreamPath, baseHandler, upstreamPub := setupHelloUpstream(t)
	if len(deb) < 20 {
		t.Fatalf("test .deb too small to split meaningfully: %d bytes", len(deb))
	}
	half := len(deb) / 2
	releaseSecondHalf := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+upstreamPath {
			baseHandler(w, r)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("httptest ResponseWriter does not support Flush")
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(deb[:half]); err != nil {
			t.Errorf("write first half: %v", err)
		}
		flusher.Flush()
		<-releaseSecondHalf
		_, _ = w.Write(deb[half:])
	}))
	defer upstream.Close()

	webServer, _ := newHelloServer(t, upstream.URL, upstreamPub)
	srv := httptest.NewServer(webServer.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	firstHalf := make([]byte, half)
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(resp.Body, firstHalf)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("reading first half: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first half -- response is not actually streaming")
	}
	if !bytes.Equal(firstHalf, deb[:half]) {
		t.Fatal("first half of the streamed response doesn't match what upstream sent")
	}

	close(releaseSecondHalf)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, deb[half:]) {
		t.Fatal("second half of the streamed response doesn't match what upstream sent")
	}
}

// TestPoolPullThroughSurvivesClientDisconnect is the direct regression test
// for detaching the fetch from the client's own request context: a client
// that gives up partway through a streaming pull-through (its own idle
// timeout, a killed apt process, a real network drop) must not abort the
// underlying fetch -- the file must still land in the cache, so the very
// next request is a fast cache hit instead of independently restarting and
// re-losing the same race against a slow upstream from scratch, which is
// exactly the repeat-failure pattern observed in production against
// ports.ubuntu.com.
func TestPoolPullThroughSurvivesClientDisconnect(t *testing.T) {
	deb, upstreamPath, baseHandler, upstreamPub := setupHelloUpstream(t)
	if len(deb) < 20 {
		t.Fatalf("test .deb too small to split meaningfully: %d bytes", len(deb))
	}
	half := len(deb) / 2
	releaseSecondHalf := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+upstreamPath {
			baseHandler(w, r)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("httptest ResponseWriter does not support Flush")
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(deb[:half]); err != nil {
			t.Errorf("write first half: %v", err)
		}
		flusher.Flush()
		<-releaseSecondHalf
		_, _ = w.Write(deb[half:])
	}))
	defer upstream.Close()

	webServer, store := newHelloServer(t, upstream.URL, upstreamPub)
	srv := httptest.NewServer(webServer.Handler())
	defer srv.Close()

	poolPath := model.PoolPath("debian", "trixie", "debian-main", "utils", "hello", "1.0", "amd64")
	url := srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb"

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	firstHalf := make([]byte, half)
	if _, err := io.ReadFull(resp.Body, firstHalf); err != nil {
		t.Fatalf("reading first half: %v", err)
	}
	if !bytes.Equal(firstHalf, deb[:half]) {
		t.Fatal("first half of the streamed response doesn't match what upstream sent")
	}

	// Simulate the client giving up mid-transfer: close the body and cancel
	// its own request context, same as a real apt client hitting an idle
	// timeout or being killed.
	resp.Body.Close()
	cancel()

	// Give the now-client-less server-side handler a moment to notice the
	// client is gone, then let the upstream finish sending the rest of the
	// file -- proving the fetch kept running regardless.
	time.Sleep(200 * time.Millisecond)
	close(releaseSecondHalf)

	deadline := time.Now().Add(5 * time.Second)
	for {
		exists, err := store.Exists(context.Background(), poolPath)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the pool file to be cached after the client disconnected -- the fetch was aborted along with the client instead of surviving it")
		}
		time.Sleep(20 * time.Millisecond)
	}

	rc, err := store.Open(context.Background(), poolPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, deb) {
		t.Fatalf("cached file is %d bytes, want the full %d-byte original -- the fetch was truncated when the client disconnected", len(got), len(deb))
	}
}

// TestPoolPullThroughDigestMismatchDoesNotCacheCorruptFile proves
// digestVerifyingReader's safety property end to end: if upstream serves
// bytes that don't match the Packages index's declared SHA256 (a corrupted
// or tampered mirror response), the client still receives whatever was
// streamed (it's responsible for its own checksum verification, same as any
// real apt client), but the pool file must never be committed to storage --
// otherwise every future request would be served that same corrupt content
// from cache instead of getting a chance to re-fetch a good copy.
func TestPoolPullThroughDigestMismatchDoesNotCacheCorruptFile(t *testing.T) {
	deb, upstreamPath, baseHandler, upstreamPub := setupHelloUpstream(t)
	corrupted := append([]byte(nil), deb...)
	corrupted[0] ^= 0xFF // same length, different content/digest

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+upstreamPath {
			baseHandler(w, r)
			return
		}
		_, _ = w.Write(corrupted)
	}))
	defer upstream.Close()

	webServer, store := newHelloServer(t, upstream.URL, upstreamPub)
	srv := httptest.NewServer(webServer.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, corrupted) {
		t.Errorf("expected the client to receive exactly what upstream served (corrupted bytes), got %d bytes matching=%v", len(body), bytes.Equal(body, corrupted))
	}

	poolPath := model.PoolPath("debian", "trixie", "debian-main", "utils", "hello", "1.0", "amd64")
	exists, err := store.Exists(context.Background(), poolPath)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expected no pool file to be cached after a digest mismatch, but one was written")
	}
}

// TestPoolPullThroughHeadDoesNotFetchUpstream proves HEAD on a not-yet-
// cached pool file is answered from already-known package metadata (size,
// name) without ever contacting upstream for the .deb itself.
func TestPoolPullThroughHeadDoesNotFetchUpstream(t *testing.T) {
	deb, upstreamPath, baseHandler, upstreamPub := setupHelloUpstream(t)

	var mu sync.Mutex
	var debHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+upstreamPath {
			mu.Lock()
			debHits++
			mu.Unlock()
			_, _ = w.Write(deb)
			return
		}
		baseHandler(w, r)
	}))
	defer upstream.Close()

	webServer, _ := newHelloServer(t, upstream.URL, upstreamPub)
	srv := httptest.NewServer(webServer.Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodHead, srv.URL+"/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(deb)) {
		t.Errorf("Content-Length = %q, want %q", got, strconv.Itoa(len(deb)))
	}

	mu.Lock()
	hits := debHits
	mu.Unlock()
	if hits != 0 {
		t.Errorf("expected HEAD to never fetch the .deb from upstream, got %d hits", hits)
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

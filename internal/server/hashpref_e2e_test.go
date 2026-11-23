package server_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"github.com/debproxy/debproxy/internal/storage"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/signing"
)

// weakStanza builds a Packages stanza carrying only MD5sum and SHA1, the
// shape of a repository that predates SHA256 in apt. sha1 overrides the
// real SHA1 when non-empty.
func weakStanza(t *testing.T, control, filename string, deb []byte, extra map[string]string) []byte {
	t.Helper()
	para, err := apt.ParseStanza(control)
	if err != nil {
		t.Fatal(err)
	}
	m := md5.Sum(deb)
	s1 := sha1.Sum(deb)
	para.Set("Filename", filename)
	para.Set("Size", strconv.Itoa(len(deb)))
	para.Set("MD5sum", hex.EncodeToString(m[:]))
	para.Set("SHA1", hex.EncodeToString(s1[:]))
	for k, v := range extra {
		para.Set(k, v)
	}
	s, err := apt.StanzaString(para)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s + "\n")
}

func weakHelloUpstream(t *testing.T, extra map[string]string) (deb []byte, upstreamURL, upstreamPub string) {
	t.Helper()
	dir := t.TempDir()
	priv := filepath.Join(dir, "upstream.priv.asc")
	pub := filepath.Join(dir, "upstream.pub.asc")
	writeKeyPair(t, priv, pub)
	key, err := signing.Load(priv)
	if err != nil {
		t.Fatal(err)
	}
	control := "Package: hello\nVersion: 1.0\nArchitecture: amd64\nSection: utils\nMaintainer: T <t@example.com>\nDescription: hello\n"
	deb = buildDeb(t, control)
	upstreamPath := "pool/main/h/hello/hello_1.0_amd64.deb"
	packages := weakStanza(t, control, upstreamPath, deb, extra)
	gz := gzipBytes(t, packages)
	inRelease, err := key.SignInline([]byte(buildUpstreamRelease(packages, gz)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/trixie/InRelease":
			_, _ = w.Write(inRelease)
		case "/dists/trixie/main/binary-amd64/Packages":
			_, _ = w.Write(packages)
		case "/dists/trixie/main/binary-amd64/Packages.gz":
			_, _ = w.Write(gz)
		case "/" + upstreamPath:
			_, _ = w.Write(deb)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return deb, srv.URL, pub
}

// waitCached polls for the pool file: the client's body completes when the
// last byte arrives, which is before the server renames the file into place.
func waitCached(t *testing.T, store storage.Storage, poolPath string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ok, err := store.Exists(context.Background(), poolPath)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A package whose upstream stanza carries only MD5sum and SHA1 is verified
// against SHA1, cached, and indexed with the SHA256 debproxy computed from
// the verified bytes, so snapshots carry a strong hash for it.
func TestPoolPullThroughWeakOnlyStanzaIsCachedAndIndexedWithSHA256(t *testing.T) {
	deb, upstreamURL, upstreamPub := weakHelloUpstream(t, nil)
	webServer, store, index := newHelloServerWithIndex(t, upstreamURL, upstreamPub)
	srv := httptest.NewServer(webServer.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, deb) {
		t.Fatalf("status %d, %d bytes (want 200 and the .deb)", resp.StatusCode, len(body))
	}
	poolPath := model.PoolPath("debian", "trixie", "debian-main", "utils", "hello", "1.0", "amd64")
	if !waitCached(t, store, poolPath) {
		t.Fatal("verified package was not cached")
	}
	entry, err := index.FindEntry(context.Background(), model.Selector{OS: "debian", Codename: "trixie"}, "hello", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("no index entry for the cached package")
	}
	if string(entry.Checksums.SHA256) != sha256hex(deb) {
		t.Fatalf("index entry SHA256 = %q, want the digest of the verified bytes", entry.Checksums.SHA256)
	}
	if entry.Checksums.SHA512 == "" {
		t.Fatal("index entry has no SHA512 although the bytes were hashed on the way in")
	}
}

// The weak hashes are not consulted when SHA256 is present: a right MD5sum
// and SHA1 beside a wrong SHA256 must not get the file cached.
func TestPoolPullThroughWrongSHA256IsNotRescuedByWeakHashes(t *testing.T) {
	_, upstreamURL, upstreamPub := weakHelloUpstream(t, map[string]string{"SHA256": strings.Repeat("0", 64)})
	webServer, store := newHelloServer(t, upstreamURL, upstreamPub)
	srv := httptest.NewServer(webServer.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/live/debian/pool/debian/trixie/debian-main/utils/h/hello/hello_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	poolPath := model.PoolPath("debian", "trixie", "debian-main", "utils", "hello", "1.0", "amd64")
	exists, err := store.Exists(context.Background(), poolPath)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("package with a wrong SHA256 was cached because its MD5sum and SHA1 matched")
	}
}

package ingest

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/upstream"
)

func hexOf(algo apt.HashAlgo, data []byte) string {
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

// recordingIndex keeps the last entry handed to UpsertEntry.
type recordingIndex struct {
	stubIndex
	last *model.IndexEntry
}

func (r *recordingIndex) UpsertEntry(_ context.Context, e model.IndexEntry) error {
	r.last = &e
	return nil
}

func readAll(t *testing.T, d *digestVerifyingReader) error {
	t.Helper()
	var sink bytes.Buffer
	_, err := sink.ReadFrom(d)
	return err
}

func TestDigestVerifyingReaderVerifiesStrongestAndComputesSHA2(t *testing.T) {
	content := []byte("package bytes")
	for _, algo := range apt.HashPreference {
		var h apt.Hashes
		h.Set(algo, hexOf(algo, content))
		d := newDigestVerifyingReader(bytes.NewReader(content), nil, h)
		if err := readAll(t, d); err != nil {
			t.Fatalf("%s alone: %v", algo, err)
		}
		cs := d.checksums()
		if string(cs.SHA256) != hexOf(apt.HashSHA256, content) || string(cs.SHA512) != hexOf(apt.HashSHA512, content) {
			t.Fatalf("%s: computed checksums %+v are wrong", algo, cs)
		}
	}
}

func TestDigestVerifyingReaderWeakMatchDoesNotRescueStrongMismatch(t *testing.T) {
	content := []byte("package bytes")
	h := apt.Hashes{
		MD5:    hexOf(apt.HashMD5, content),
		SHA1:   hexOf(apt.HashSHA1, content),
		SHA256: hexOf(apt.HashSHA256, []byte("other bytes")),
	}
	d := newDigestVerifyingReader(bytes.NewReader(content), nil, h)
	err := readAll(t, d)
	if !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Fatalf("err = %v, want digest mismatch", err)
	}
	if !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("mismatch does not name SHA256: %v", err)
	}
}

func TestDigestVerifyingReaderWeakOnlyMismatchFails(t *testing.T) {
	content := []byte("package bytes")
	h := apt.Hashes{SHA1: hexOf(apt.HashSHA1, []byte("other"))}
	d := newDigestVerifyingReader(bytes.NewReader(content), nil, h)
	if err := readAll(t, d); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestDigestVerifyingReaderNoDigestIsAnError(t *testing.T) {
	d := newDigestVerifyingReader(bytes.NewReader([]byte("x")), nil, apt.Hashes{})
	if err := readAll(t, d); !errors.Is(err, apt.ErrNoDigest) {
		t.Fatalf("err = %v, want ErrNoDigest", err)
	}
}

func weakPkg(content []byte) avail.Pkg {
	return avail.Pkg{
		Name: "hello", Version: "1.0", Arch: "amd64", Component: "main",
		Filename: "pool/main/h/hello/hello_1.0_amd64.deb",
		PoolPath: "pool/debian/trixie/up/utils/h/hello/hello_1.0_amd64.deb",
		Size:     int64(len(content)),
		MD5:      hexOf(apt.HashMD5, content),
		SHA1:     hexOf(apt.HashSHA1, content),
		Upstream: model.UpstreamSource{Name: "up"},
	}
}

// A package advertised with weak digests only is verified by SHA1 and
// indexed with the SHA-2 digests computed from the verified bytes.
func TestCacheStreamingBodyWeakOnlyPackageIsIndexedWithComputedSHA2(t *testing.T) {
	content := []byte("hello deb content")
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	idx := &recordingIndex{}
	in := New(store, idx, nil, nil, nil)
	p := weakPkg(content)
	if err := in.CacheStreamingBody(context.Background(), "debian", "trixie", p, bytes.NewReader(content), false, nil); err != nil {
		t.Fatalf("CacheStreamingBody: %v", err)
	}
	ok, err := store.Exists(context.Background(), p.PoolPath)
	if err != nil || !ok {
		t.Fatalf("stored: %v, %v", ok, err)
	}
	if idx.last == nil {
		t.Fatal("no index entry upserted")
	}
	if string(idx.last.Checksums.SHA256) != hexOf(apt.HashSHA256, content) || string(idx.last.Checksums.SHA512) != hexOf(apt.HashSHA512, content) {
		t.Fatalf("entry checksums %+v are not the computed SHA-2 digests", idx.last.Checksums)
	}
}

func TestCacheStreamingBodyWrongSHA256NotRescuedByWeakDigests(t *testing.T) {
	content := []byte("hello deb content")
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	idx := &recordingIndex{}
	in := New(store, idx, nil, nil, nil)
	p := weakPkg(content)
	p.SHA256 = strings.Repeat("0", 64)
	err = in.CacheStreamingBody(context.Background(), "debian", "trixie", p, bytes.NewReader(content), false, nil)
	if !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Fatalf("err = %v, want digest mismatch", err)
	}
	if ok, _ := store.Exists(context.Background(), p.PoolPath); ok {
		t.Fatal("file with a wrong SHA256 was kept")
	}
	if idx.last != nil {
		t.Fatal("index entry was upserted for a rejected file")
	}
}

// The already-cached path has no stream to hash; with no SHA256 advertised
// the entry's digests come from the stored file.
func TestUpsertEntryComputesChecksumsWhenUpstreamHasNone(t *testing.T) {
	content := []byte("hello deb content")
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := weakPkg(content)
	if err := store.PutFile(context.Background(), p.PoolPath, bytes.NewReader(content), p.Size); err != nil {
		t.Fatal(err)
	}
	idx := &recordingIndex{}
	in := New(store, idx, nil, nil, nil)
	if err := in.CacheStreaming(context.Background(), "debian", "trixie", p, false, nil); err != nil {
		t.Fatalf("CacheStreaming: %v", err)
	}
	if idx.last == nil || string(idx.last.Checksums.SHA256) != hexOf(apt.HashSHA256, content) {
		t.Fatalf("entry = %+v, want computed SHA256", idx.last)
	}
}

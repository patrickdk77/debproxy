package apt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// HashAlgo names a digest the way apt does in Release sections and by-hash
// directories.
type HashAlgo string

const (
	HashMD5    HashAlgo = "MD5Sum"
	HashSHA1   HashAlgo = "SHA1"
	HashSHA256 HashAlgo = "SHA256"
	HashSHA512 HashAlgo = "SHA512"
)

// HashPreference is strongest first. It is apt's own order: a file is
// verified with the first algorithm here that the upstream listed for it,
// and the weaker ones are not consulted when a stronger one exists.
var HashPreference = []HashAlgo{HashSHA512, HashSHA256, HashSHA1, HashMD5}

var (
	ErrDigestMismatch = errors.New("digest mismatch")
	ErrNoDigest       = errors.New("no digest to verify against")
)

// Hashes holds whichever digests an upstream published for one file.
type Hashes struct {
	MD5    string
	SHA1   string
	SHA256 string
	SHA512 string
}

func (h Hashes) Get(a HashAlgo) string {
	switch a {
	case HashMD5:
		return h.MD5
	case HashSHA1:
		return h.SHA1
	case HashSHA256:
		return h.SHA256
	case HashSHA512:
		return h.SHA512
	}
	return ""
}

func (h *Hashes) Set(a HashAlgo, digest string) {
	switch a {
	case HashMD5:
		h.MD5 = digest
	case HashSHA1:
		h.SHA1 = digest
	case HashSHA256:
		h.SHA256 = digest
	case HashSHA512:
		h.SHA512 = digest
	}
}

// Best returns the strongest digest present, or ("", "") when there is none.
func (h Hashes) Best() (HashAlgo, string) {
	for _, a := range HashPreference {
		if d := h.Get(a); d != "" {
			return a, d
		}
	}
	return "", ""
}

func (h Hashes) Empty() bool {
	_, d := h.Best()
	return d == ""
}

// NewHash returns a hasher for a. It panics on an unknown algorithm, which
// cannot come out of Best.
func NewHash(a HashAlgo) hash.Hash {
	switch a {
	case HashMD5:
		return md5.New()
	case HashSHA1:
		return sha1.New()
	case HashSHA256:
		return sha256.New()
	case HashSHA512:
		return sha512.New()
	}
	panic("apt: unknown hash algorithm " + string(a))
}

// Verify checks data against the strongest digest present.
func (h Hashes) Verify(data []byte) error {
	algo, want := h.Best()
	if want == "" {
		return ErrNoDigest
	}
	hh := NewHash(algo)
	hh.Write(data)
	got := hex.EncodeToString(hh.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%w: %s got %s want %s", ErrDigestMismatch, algo, got, want)
	}
	return nil
}

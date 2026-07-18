package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/debproxy/debproxy/internal/signing"
)

// writeGeneratedKey writes a freshly generated armored public key into dir and
// returns its path. Self-contained: no dependency on any checked-in key corpus.
func writeGeneratedKey(t *testing.T, dir string) string {
	t.Helper()
	e, err := openpgp.NewEntity("Sample Key", "", "sample@example.test", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()

	dst := filepath.Join(dir, "real.asc")
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestReadKeyFile_EmptyIsNotAnError(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.gpg")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := readKeyFile(empty)
	if err != nil {
		t.Errorf("readKeyFile(empty) = %v, want nil error (empty keyrings are valid)", err)
	}
	if len(keys) != 0 {
		t.Errorf("readKeyFile(empty) returned %d keys, want 0", len(keys))
	}

	whitespace := filepath.Join(dir, "ws.gpg")
	if err := os.WriteFile(whitespace, []byte("\n\n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(whitespace); err != nil {
		t.Errorf("readKeyFile(whitespace-only) = %v, want nil error", err)
	}
}

// TestLoadKeyring_TestdataCorpus is the standing guard for the operator
// requirement that every real-world key format loads. It loads every file in
// testdata/ (a committed corpus of vendor repository keys, armored and binary,
// plus empty removed-keys placeholders and the debproxy signing secret keys).
// Each must load without error; empty placeholders load as zero keys. Secret
// keys must additionally load through signing.Load and expose a private key.
func TestLoadKeyring_TestdataCorpus(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Skipf("no testdata corpus present: %v", err)
	}
	seen := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		seen++
		p := filepath.Join("testdata", e.Name())
		if _, err := readKeyFile(p); err != nil {
			t.Errorf("readKeyFile(%s) = %v, want it to load", e.Name(), err)
		}
		if strings.Contains(e.Name(), "secret") {
			k, err := signing.Load(p)
			if err != nil {
				t.Errorf("signing.Load(%s) = %v, want a usable signing key", e.Name(), err)
			} else if k == nil {
				t.Errorf("signing.Load(%s) = nil key", e.Name())
			}
		}
	}
	if seen == 0 {
		t.Skip("testdata corpus is empty")
	}
	t.Logf("loaded %d testdata key files", seen)
}

func TestLoadKeyring_SkipsEmptyButRequiresOneKey(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "removed-keys.gpg")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// An empty file listed alone leaves the upstream with no verification key:
	// that must still be an error.
	if _, err := loadKeyring([]string{empty}); err == nil {
		t.Error("loadKeyring([empty]) = nil error, want an error (no usable keys)")
	}

	// An empty file alongside a real key is tolerated: the empty one is skipped.
	real := writeGeneratedKey(t, dir)
	kr, err := loadKeyring([]string{real, empty})
	if err != nil {
		t.Fatalf("loadKeyring([real, empty]) = %v, want success", err)
	}
	if len(kr) == 0 {
		t.Error("loadKeyring([real, empty]) returned no keys")
	}
}

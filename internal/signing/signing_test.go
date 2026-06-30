package signing_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/debproxy/debproxy/internal/signing"
)

type memWriter struct {
	files map[string][]byte
}

func (m *memWriter) WriteFile(_ context.Context, relPath string, r io.Reader, _ int64) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	m.files[relPath] = data
	return nil
}

func TestPublishProducesAscAndGpg(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "debproxy.asc")
	writePrivateKey(t, keyPath)

	key, err := signing.Load(keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if key.Fingerprint() == "" {
		t.Fatal("expected non-empty fingerprint")
	}

	w := &memWriter{}
	names, err := key.Publish(context.Background(), w)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(names) != 4 {
		t.Fatalf("expected 4 published files, got %d: %v", len(names), names)
	}

	fp := key.Fingerprint()
	for _, name := range []string{
		"keys/" + fp + ".asc",
		"keys/" + fp + ".gpg",
		"keys/debproxy.asc",
		"keys/debproxy.gpg",
	} {
		if _, ok := w.files[name]; !ok {
			t.Fatalf("missing published file %q", name)
		}
	}

	asc := w.files["keys/debproxy.asc"]
	if !bytes.Contains(asc, []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		t.Fatal("asc file is not ASCII-armored public key")
	}

	bin := w.files["keys/debproxy.gpg"]
	if _, err := openpgp.ReadKeyRing(bytes.NewReader(bin)); err != nil {
		t.Fatalf("gpg file is not a valid binary keyring: %v", err)
	}
	if bytes.Contains(bin, []byte("BEGIN PGP")) {
		t.Fatal("gpg file should be binary, not armored")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "debproxy.asc")
	writePrivateKey(t, keyPath)
	key, err := signing.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	keyring, err := key.PublicKeyring()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Origin: debproxy\nCodename: trixie\n")

	inline, err := key.SignInline(msg)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := signing.VerifyClearsigned(inline, keyring)
	if err != nil {
		t.Fatalf("verify inline: %v", err)
	}
	if !bytes.Contains(body, []byte("Codename: trixie")) {
		t.Fatalf("unexpected verified body: %q", body)
	}

	detached, err := key.SignDetached(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.VerifyDetached(msg, detached, keyring); err != nil {
		t.Fatalf("verify detached: %v", err)
	}
	if _, err := signing.VerifyDetached([]byte("tampered"), detached, keyring); err == nil {
		t.Fatal("expected verification failure on tampered body")
	}
}

func writePrivateKey(t *testing.T, path string) {
	t.Helper()
	entity, err := openpgp.NewEntity("debproxy-sign", "", "sign@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := armor.Encode(f, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

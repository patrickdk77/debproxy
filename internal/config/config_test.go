package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/debproxy/debproxy/internal/config"
)

func TestLoadResolvesLayouts(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.asc")
	writeTestKey(t, keyPath)

	cfgPath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
storage:
  backend: filesystem
  filesystem:
    root: /tmp/debproxy
upstreams:
  debian-main:
    url: http://deb.debian.org/debian
    keys:
      - `+strconv.Quote(keyPath)+`
  debian-security:
    url: http://security.debian.org/debian-security
    suite: "{codename}-security"
    keys:
      - `+strconv.Quote(keyPath)+`
layouts:
  - os: debian
    architectures: [amd64, all]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-main, debian-security]
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ResolvedLayouts) != 1 {
		t.Fatalf("expected 1 layout, got %d", len(cfg.ResolvedLayouts))
	}
	layout := cfg.ResolvedLayouts[0]
	if layout.Codename != "trixie" || layout.Component != "main" {
		t.Fatalf("unexpected layout %+v", layout)
	}
	if len(layout.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(layout.Upstreams))
	}
	if layout.Upstreams[1].Suite != "trixie-security" {
		t.Fatalf("expected suite trixie-security, got %q", layout.Upstreams[1].Suite)
	}
}

func TestLoadAcceptsBinaryGPGKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.gpg")
	writeTestKeyBinary(t, keyPath)

	cfgPath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
storage:
  backend: filesystem
  filesystem:
    root: /tmp/debproxy
upstreams:
  debian-main:
    url: http://deb.debian.org/debian
    keys:
      - `+strconv.Quote(keyPath)+`
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-main]
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load with binary key: %v", err)
	}
	if len(cfg.ResolvedLayouts) != 1 {
		t.Fatalf("expected 1 layout, got %d", len(cfg.ResolvedLayouts))
	}
	if len(cfg.ResolvedLayouts[0].Upstreams[0].VerifyKeys) == 0 {
		t.Fatal("expected VerifyKeys to be populated from binary key")
	}
}

func writeTestKey(t *testing.T, path string) {
	t.Helper()
	entity, err := openpgp.NewEntity("debproxy-test", "", "debproxy@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := armor.Encode(f, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTestKeyBinary(t *testing.T, path string) {
	t.Helper()
	entity, err := openpgp.NewEntity("debproxy-test-binary", "", "debproxy-bin@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := entity.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

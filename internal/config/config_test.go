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

func minimalConfigYAML(keyPath, extra string) string {
	return `
storage:
  backend: filesystem
  filesystem:
    root: /tmp/debproxy
` + extra + `
upstreams:
  debian-main:
    url: http://deb.debian.org/debian
    keys:
      - ` + strconv.Quote(keyPath) + `
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-main]
`
}

func TestLoadAcceptsUpstreamNetworkIPv4(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.asc")
	writeTestKey(t, keyPath)

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(minimalConfigYAML(keyPath, `upstream_network: "ipv4"`)), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamNetwork != "ipv4" {
		t.Errorf("UpstreamNetwork = %q, want %q", cfg.UpstreamNetwork, "ipv4")
	}
}

// TestUpstreamNetworkPerUpstreamOverridesGlobalDefault proves the precedence
// this whole feature is about: a specific upstream's own upstream_network
// wins over the global default for that upstream, while a sibling upstream
// with no override just inherits the global default -- letting an operator
// force IPv4 for one broken mirror (e.g. ports.ubuntu.com) without affecting
// every other upstream.
func TestUpstreamNetworkPerUpstreamOverridesGlobalDefault(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.asc")
	writeTestKey(t, keyPath)

	cfgPath := filepath.Join(dir, "config.yaml")
	yamlContent := `
storage:
  backend: filesystem
  filesystem:
    root: /tmp/debproxy
upstream_network: "ipv6"
upstreams:
  debian-main:
    url: http://deb.debian.org/debian
    keys:
      - ` + strconv.Quote(keyPath) + `
  ubuntu-ports-main:
    url: http://ports.ubuntu.com/ubuntu-ports
    upstream_network: "ipv4"
    keys:
      - ` + strconv.Quote(keyPath) + `
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-main, ubuntu-ports-main]
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ResolvedLayouts) != 1 {
		t.Fatalf("expected 1 resolved layout, got %d", len(cfg.ResolvedLayouts))
	}
	byName := map[string]string{}
	for _, up := range cfg.ResolvedLayouts[0].Upstreams {
		byName[up.Name] = up.Network
	}
	if byName["debian-main"] != "ipv6" {
		t.Errorf("debian-main resolved Network = %q, want %q (the global default)", byName["debian-main"], "ipv6")
	}
	if byName["ubuntu-ports-main"] != "ipv4" {
		t.Errorf("ubuntu-ports-main resolved Network = %q, want %q (its own override)", byName["ubuntu-ports-main"], "ipv4")
	}
}

// TestLoadRejectsUnknownUpstreamNetwork is the bad-data counterpart: a typo'd
// or otherwise unrecognized upstream_network value must fail Load with a
// clear error rather than silently falling back to dual-stack behavior,
// which would leave a broken-IPv6 deployment believing it had opted out when
// it hadn't.
func TestLoadRejectsUnknownUpstreamNetwork(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.asc")
	writeTestKey(t, keyPath)

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(minimalConfigYAML(keyPath, `upstream_network: "ipv5"`)), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(cfgPath); err == nil {
		t.Fatal("expected Load to reject an unknown upstream_network value, got nil error")
	}
}

// TestLoadRejectsUnknownPerUpstreamNetwork is TestLoadRejectsUnknownUpstreamNetwork's
// counterpart for the per-upstream override specifically -- a typo there must
// be caught too, not just at the global level.
func TestLoadRejectsUnknownPerUpstreamNetwork(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.asc")
	writeTestKey(t, keyPath)

	cfgPath := filepath.Join(dir, "config.yaml")
	yamlContent := `
storage:
  backend: filesystem
  filesystem:
    root: /tmp/debproxy
upstreams:
  debian-main:
    url: http://deb.debian.org/debian
    upstream_network: "ipv5"
    keys:
      - ` + strconv.Quote(keyPath) + `
layouts:
  - os: debian
    architectures: [amd64]
    codenames:
      - codename: trixie
        components:
          - component: main
            upstreams: [debian-main]
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(cfgPath); err == nil {
		t.Fatal("expected Load to reject an unknown per-upstream upstream_network value, got nil error")
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

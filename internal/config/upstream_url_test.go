package config_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
)

const fsStorage = `storage:
  backend: filesystem
  filesystem:
    root: /tmp/debproxy
`

const s3Storage = `storage:
  backend: s3
  s3:
    bucket: cache
    region: eu-west-1
    endpoint: http://minio:9000
    force_path_style: true
`

// loadUpstreams loads a config with the given storage block and upstream
// bodies (keyed by name, each already indented four spaces, keys added
// here) and one debian/trixie/main layout listing every upstream.
func loadUpstreams(t *testing.T, storage string, upstreams map[string]string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.asc")
	writeTestKey(t, keyPath)

	var b strings.Builder
	b.WriteString(storage)
	b.WriteString("upstreams:\n")
	var names []string
	for name, body := range upstreams {
		names = append(names, name)
		b.WriteString("  " + name + ":\n")
		b.WriteString(body)
		b.WriteString("    keys:\n      - " + strconv.Quote(keyPath) + "\n")
	}
	b.WriteString("layouts:\n  - os: debian\n    architectures: [amd64]\n    codenames:\n      - codename: trixie\n        components:\n          - component: main\n            upstreams: [" + strings.Join(names, ", ") + "]\n")

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return config.Load(cfgPath)
}

func resolvedUpstream(t *testing.T, cfg *config.Config, name string) model.UpstreamSource {
	t.Helper()
	for _, src := range cfg.ResolvedLayouts[0].Upstreams {
		if src.Name == name {
			return src
		}
	}
	t.Fatalf("upstream %q not resolved", name)
	return model.UpstreamSource{}
}

func TestLoadMovesURLCredentialsIntoUsernamePassword(t *testing.T) {
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{"up": "    url: s3://AKIATEST:sec%2Fret+x@bucket/debian\n"})
	if err != nil {
		t.Fatal(err)
	}
	src := resolvedUpstream(t, cfg, "up")
	if src.URL != "s3://bucket/debian" {
		t.Fatalf("URL = %q, want s3://bucket/debian", src.URL)
	}
	if src.Username != "AKIATEST" || src.Password != "sec/ret+x" {
		t.Fatalf("credentials = %q/%q, want AKIATEST/sec/ret+x", src.Username, src.Password)
	}
}

// A password inside the URL is taken literally: an http upstream whose
// password starts with "$" has always been sent as written.
func TestLoadKeepsURLPasswordLiteral(t *testing.T) {
	t.Setenv("ecret", "from-env")
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{"up": "    url: http://u:$ecret@host/x\n"})
	if err != nil {
		t.Fatal(err)
	}
	src := resolvedUpstream(t, cfg, "up")
	if src.URL != "http://host/x" || src.Password != "$ecret" {
		t.Fatalf("URL = %q password = %q, want http://host/x and the literal $ecret", src.URL, src.Password)
	}
}

func TestLoadExpandsEnvRefInPasswordKey(t *testing.T) {
	t.Setenv("S3_SECRET", "from-env")
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{"up": "    url: s3://bucket\n    username: AKIATEST\n    password: $S3_SECRET\n"})
	if err != nil {
		t.Fatal(err)
	}
	src := resolvedUpstream(t, cfg, "up")
	if src.Username != "AKIATEST" || src.Password != "from-env" {
		t.Fatalf("credentials = %q/%q, want AKIATEST/from-env", src.Username, src.Password)
	}
}

func TestLoadLowercasesURLScheme(t *testing.T) {
	cfg, err := loadUpstreams(t, s3Storage, map[string]string{"up": "    url: S3://bucket/x\n"})
	if err != nil {
		t.Fatal(err)
	}
	src := resolvedUpstream(t, cfg, "up")
	if src.URL != "s3://bucket/x" || src.S3.Region != "eu-west-1" {
		t.Fatalf("URL = %q S3 = %+v, want s3://bucket/x with the storage.s3 defaults", src.URL, src.S3)
	}
}

func TestLoadStripsCredentialsFromHTTPURLAndKeepsPlaceholders(t *testing.T) {
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{"up": "    url: http://bearer:tok@{os}.example.com/{codename}/x\n"})
	if err != nil {
		t.Fatal(err)
	}
	src := resolvedUpstream(t, cfg, "up")
	if src.URL != "http://debian.example.com/trixie/x" {
		t.Fatalf("URL = %q, want http://debian.example.com/trixie/x", src.URL)
	}
	if src.Username != "bearer" || src.Password != "tok" {
		t.Fatalf("credentials = %q/%q, want bearer/tok", src.Username, src.Password)
	}
	if src.S3 != (model.S3Options{}) {
		t.Fatalf("http upstream got S3 options %+v", src.S3)
	}
}

func TestLoadKeepsURLWithoutCredentialsByteForByte(t *testing.T) {
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{"up": "    url: http://{os}.example.com/{codename}/x/\n    username: u\n    password: p\n"})
	if err != nil {
		t.Fatal(err)
	}
	src := resolvedUpstream(t, cfg, "up")
	if src.URL != "http://debian.example.com/trixie/x/" || src.Username != "u" || src.Password != "p" {
		t.Fatalf("got URL %q credentials %q/%q", src.URL, src.Username, src.Password)
	}
}

func TestLoadRejectsBadUpstreamURLs(t *testing.T) {
	cases := map[string]string{
		"credentials in url and fields":      "    url: s3://k:topsecret@bucket/x\n    username: u\n    password: p\n",
		"unknown scheme":                     "    url: ftp://u:topsecret@host/x\n",
		"s3 without bucket":                  "    url: s3:///topsecret\n",
		"query string":                       "    url: s3://k:topsecret@bucket/x?region=1\n",
		"fragment":                           "    url: http://host/x#topsecret\n",
		"unparsable":                         "    url: http://host:topsecret:1/x\n",
		"s3 secret with a leading slash":     "    url: s3://k:/topsecret@bucket/x\n",
		"s3 secret with digits then a slash": "    url: s3://k:12/topsecret@bucket/x\n",
		"s3 host with a port":                "    url: s3://bucket:9000/x\n",
		"s3 at sign after the host":          "    url: s3://bucket/x@topsecret\n",
		"s3 settings on an http url":         "    url: http://host/x\n    s3:\n      region: us-east-1\n",
		"s3 key id without a secret":         "    url: s3://bucket/x\n    username: AKIA\n",
		"s3 secret without a key id":         "    url: s3://bucket/x\n    password: topsecret\n",
		"s3 secret from an unset variable":   "    url: s3://bucket/x\n    username: AKIA\n    password: $DEBPROXY_TEST_UNSET_SECRET\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadUpstreams(t, fsStorage, map[string]string{"up": body})
			if err == nil {
				t.Fatal("expected Load to fail, got nil error")
			}
			if !strings.Contains(err.Error(), `upstream "up"`) {
				t.Fatalf("error does not name the upstream: %v", err)
			}
			if strings.Contains(err.Error(), "topsecret") {
				t.Fatalf("error leaks the URL secret: %v", err)
			}
		})
	}
}

func TestLoadS3UpstreamTakesStorageS3Defaults(t *testing.T) {
	cfg, err := loadUpstreams(t, s3Storage, map[string]string{
		"plain":    "    url: s3://bucket/x\n",
		"endpoint": "    url: s3://bucket/y\n    s3:\n      endpoint: https://s3.us-east-1.amazonaws.com\n      force_path_style: false\n",
		"region":   "    url: s3://bucket/z\n    s3:\n      region: us-east-1\n",
		"http":     "    url: http://host/x\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.S3Options{
		"plain":    {Region: "eu-west-1", Endpoint: "http://minio:9000", ForcePathStyle: true},
		"endpoint": {Region: "eu-west-1", Endpoint: "https://s3.us-east-1.amazonaws.com", ForcePathStyle: false},
		"region":   {Region: "us-east-1", Endpoint: "http://minio:9000", ForcePathStyle: true},
		"http":     {},
	}
	for name, w := range want {
		if got := resolvedUpstream(t, cfg, name).S3; got != w {
			t.Errorf("%s: S3 = %+v, want %+v", name, got, w)
		}
	}
}

func TestLoadS3UpstreamOnFilesystemStorageHasNoDefaults(t *testing.T) {
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{
		"plain": "    url: s3://bucket/x\n",
		"own":   "    url: s3://bucket/y\n    s3:\n      region: us-east-1\n      endpoint: http://minio:9000\n      force_path_style: true\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resolvedUpstream(t, cfg, "plain").S3; got != (model.S3Options{}) {
		t.Errorf("plain: S3 = %+v, want empty", got)
	}
	want := model.S3Options{Region: "us-east-1", Endpoint: "http://minio:9000", ForcePathStyle: true}
	if got := resolvedUpstream(t, cfg, "own").S3; got != want {
		t.Errorf("own: S3 = %+v, want %+v", got, want)
	}
}

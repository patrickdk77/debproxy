package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"gopkg.in/yaml.v3"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/webhook"
)

const (
	BackendFilesystem = "filesystem"
	BackendS3         = "s3"
)

// Config is the top-level application configuration.
type Config struct {
	LogLevel        string                 `yaml:"log_level"`
	Storage         StorageConfig          `yaml:"storage"`
	UserAgent       string                 `yaml:"user_agent"`
	Webhooks        []webhook.Def          `yaml:"webhooks"`
	Upstreams       map[string]UpstreamDef `yaml:"upstreams"`
	Layouts         []OSLayout             `yaml:"layouts"`
	Signing         SigningConfig          `yaml:"signing"`
	Schedule        ScheduleConfig         `yaml:"schedule"`
	// MetricsAddr is the listen address for the Prometheus metrics endpoint
	// (e.g. ":9090"). The endpoint is exposed at /metrics on this address.
	// Leave empty to disable metrics.
	MetricsAddr string `yaml:"metrics_addr"`

	ResolvedLayouts []model.Layout `yaml:"-"`
}

// ScheduleConfig holds all periodic scheduling settings.
type ScheduleConfig struct {
	// Refresh controls how often the server re-fetches upstream package indices
	// in the background. Accepts a Go duration string (e.g. "6h", "12h").
	// Empty string or "0" disables periodic background refreshing.
	Refresh string `yaml:"refresh"`
	// Snapshot controls when the server automatically publishes snapshots while
	// running in serve mode. Three formats are accepted:
	//   "daily@HH:MM"      every day at a fixed UTC time (e.g. "daily@03:00")
	//   "day@HH:MM"        every week on that day (e.g. "sunday@03:00")
	//   Go duration string every N hours with up to 5 min jitter (e.g. "24h")
	// Empty string or "0" disables automatic snapshots.
	Snapshot string `yaml:"snapshot"`
	// History is the maximum number of snapshots to retain. A snapshot is only
	// deleted when BOTH History and Age are exceeded. 0 disables count-based pruning.
	History int `yaml:"history"`
	// Age is the maximum age of a snapshot before it becomes eligible for deletion.
	// Accepts a Go duration string with optional "d" suffix (e.g. "90d", "720h").
	// A snapshot is only deleted when BOTH History and Age are exceeded.
	// Empty string or "0" disables age-based pruning.
	Age string `yaml:"age"`
	// Cleanup controls when the server automatically prunes old snapshots and runs
	// pool GC while in serve mode. Accepts the same format as Snapshot.
	// Empty string or "0" disables automatic cleanup.
	Cleanup string `yaml:"cleanup"`
	// GCGrace is the minimum age a pool/src file must reach before pool/src GC
	// will delete it as unreferenced. This protects against a race between a
	// concurrent cache write (store.PutFile followed some time later by a
	// metadata index commit) and a GC pass building its "keep" set from the
	// index in between those two steps. Accepts a Go duration string (e.g.
	// "30m", "2h"). Empty string or "0" uses the built-in default of 1 hour --
	// this is a safety margin, not a feature to casually disable.
	GCGrace string `yaml:"gc_grace"`
}

// CompressionLevel is a YAML-compatible compression setting.
// false decodes as CompressionDisabled (-1).
// true or absent decodes as CompressionDefault (0), meaning use the built-in default.
// A positive integer decodes as that explicit level.
type CompressionLevel int

const (
	CompressionDisabled CompressionLevel = -1
	CompressionDefault  CompressionLevel = 0
)

func (c *CompressionLevel) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case "!!bool":
		var b bool
		if err := value.Decode(&b); err != nil {
			return err
		}
		if b {
			*c = CompressionDefault
		} else {
			*c = CompressionDisabled
		}
	case "!!int":
		var n int
		if err := value.Decode(&n); err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("compression level must be non-negative, got %d", n)
		}
		*c = CompressionLevel(n)
	default:
		return fmt.Errorf("compression level must be a boolean or integer, got %s", value.Tag)
	}
	return nil
}

// ResolveLevel maps a CompressionLevel to a concrete integer for publish.
// CompressionDisabled returns 0 (which publish treats as disabled).
// CompressionDefault returns def.
// Any positive value returns itself.
func ResolveLevel(c CompressionLevel, def int) int {
	switch {
	case c < 0:
		return 0
	case c == 0:
		return def
	default:
		return int(c)
	}
}

// CompressionFormatConfig holds per-format compression settings for one path
// (snapshot or live). Fields are pointers so "absent from YAML" (nil) can be
// told apart from "explicitly set to true" (&CompressionDefault) -- both
// decode to the same underlying zero value otherwise, which matters for XZ:
// its live default is disabled, but an explicit `xz: true` must still enable
// it rather than being indistinguishable from never having set the key.
type CompressionFormatConfig struct {
	GZip  *CompressionLevel `yaml:"gzip"`
	ZStd  *CompressionLevel `yaml:"zstd"`
	XZ    *CompressionLevel `yaml:"xz"`
	BZip2 *CompressionLevel `yaml:"bzip2"`
}

// CompressionConfig holds compression settings for snapshot and live publishing.
type CompressionConfig struct {
	Snapshot CompressionFormatConfig `yaml:"snapshot"`
	Live     CompressionFormatConfig `yaml:"live"`
}

// resolveLevelPtr is the nil-aware counterpart of ResolveLevel: an absent
// field (nil) uses def, same as an explicit CompressionDefault (true) would.
func resolveLevelPtr(c *CompressionLevel, def int) int {
	if c == nil {
		return def
	}
	return ResolveLevel(*c, def)
}

// xzEnabled reports whether XZ should be enabled given fc (nil = never set
// in YAML) and whatever the calling mode's default is when unset.
func xzEnabled(fc *CompressionLevel, enabledByDefault bool) bool {
	if fc == nil {
		return enabledByDefault
	}
	return *fc != CompressionDisabled
}

// ResolveSnapshot returns concrete compression settings for snapshot publishing,
// applying built-in defaults where fields are absent or set to true.
func (c CompressionConfig) ResolveSnapshot() publish.Compression {
	def := publish.DefaultSnapshotCompression
	fc := c.Snapshot
	return publish.Compression{
		GZip: resolveLevelPtr(fc.GZip, def.GZip),
		ZStd: resolveLevelPtr(fc.ZStd, def.ZStd),
		XZ:   xzEnabled(fc.XZ, def.XZ), // default=enabled; user sets false to disable
	}
}

// ResolveLive returns concrete compression settings for live publishing,
// applying built-in defaults where fields are absent or set to true.
func (c CompressionConfig) ResolveLive() publish.Compression {
	def := publish.DefaultLiveCompression
	fc := c.Live
	return publish.Compression{
		GZip: resolveLevelPtr(fc.GZip, def.GZip),
		ZStd: resolveLevelPtr(fc.ZStd, def.ZStd),
		XZ:   xzEnabled(fc.XZ, def.XZ), // default=disabled; true/any explicit level enables
	}
}

type StorageConfig struct {
	Backend     string              `yaml:"backend"`
	Filesystem  FilesystemConfig    `yaml:"filesystem"`
	S3          S3Config            `yaml:"s3"`
	Compression CompressionConfig   `yaml:"compression"`
}

type FilesystemConfig struct {
	Root string `yaml:"root"`
}

type S3Config struct {
	Bucket string `yaml:"bucket"`
	Region string `yaml:"region"`
	Prefix string `yaml:"prefix"`
}

type SigningConfig struct {
	PrivateKey string `yaml:"private_key"`
}

// UpstreamDef is a global upstream definition referenced by name from layouts.
type UpstreamDef struct {
	URL           string   `yaml:"url"`
	Suite         string   `yaml:"suite"`
	Component     string   `yaml:"component"`
	Architectures []string `yaml:"architectures"`
	AutoUpdate    bool     `yaml:"auto_update"`
	Keys          []string `yaml:"keys"`
	// Username and Password enable HTTP Basic Auth for authenticated upstreams
	// such as Ubuntu ESM/Pro (esm.ubuntu.com). If Password starts with "$",
	// it is treated as an environment variable name and expanded at load time.
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type OSLayout struct {
	OS            string           `yaml:"os"`
	Architectures []string         `yaml:"architectures"`
	HashTypes     []string         `yaml:"hash_types"`
	Codenames     []CodenameLayout `yaml:"codenames"`
}

type CodenameLayout struct {
	Codename      string            `yaml:"codename"`
	Architectures []string          `yaml:"architectures"`
	HashTypes     []string          `yaml:"hash_types"`
	Components    []ComponentLayout `yaml:"components"`
}

type ComponentLayout struct {
	Component     string   `yaml:"component"`
	Architectures []string `yaml:"architectures"`
	Upstreams     []string `yaml:"upstreams"`
	// Sources enables pull-through of deb-src (source package) requests for
	// this component. When true, FetchSources is set on each resolved UpstreamSource.
	Sources bool `yaml:"sources"`
}

// Load reads and validates configuration from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyEnvOverrides(cfg)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.resolveLayouts(); err != nil {
		return nil, err
	}
	cfg.applyLogLevel()
	return cfg, nil
}

func (c *Config) applyLogLevel() {
	var level slog.Level
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("DEBPROXY_STORAGE_FILESYSTEM_ROOT"); v != "" {
		cfg.Storage.Filesystem.Root = v
	}
	if v := os.Getenv("DEBPROXY_STORAGE_BACKEND"); v != "" {
		cfg.Storage.Backend = v
	}
}

func (c *Config) validate() error {
	switch c.Storage.Backend {
	case BackendFilesystem, BackendS3:
	default:
		return fmt.Errorf("unknown storage backend %q", c.Storage.Backend)
	}
	if c.Storage.Backend == BackendFilesystem && c.Storage.Filesystem.Root == "" {
		return fmt.Errorf("storage.filesystem.root is required")
	}

	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	if len(c.Layouts) == 0 {
		return fmt.Errorf("at least one layout is required")
	}
	return nil
}

func (c *Config) resolveLayouts() error {
	keyrings := make(map[string]openpgp.EntityList, len(c.Upstreams))
	for name, def := range c.Upstreams {
		if def.URL == "" {
			return fmt.Errorf("upstream %q: url is required", name)
		}
		if len(def.Keys) == 0 {
			return fmt.Errorf("upstream %q: at least one key is required", name)
		}
		kr, err := loadKeyring(def.Keys)
		if err != nil {
			return fmt.Errorf("upstream %q keys: %w", name, err)
		}
		keyrings[name] = kr
	}

	var resolved []model.Layout
	for _, osLayout := range c.Layouts {
		if osLayout.OS == "" {
			return fmt.Errorf("layout os is required")
		}
		for _, cn := range osLayout.Codenames {
			if cn.Codename == "" {
				return fmt.Errorf("layout %q: codename is required", osLayout.OS)
			}
			for _, comp := range cn.Components {
				if comp.Component == "" {
					return fmt.Errorf("layout %s/%s: component is required", osLayout.OS, cn.Codename)
				}
				if len(comp.Upstreams) == 0 {
					return fmt.Errorf("layout %s/%s/%s: at least one upstream is required", osLayout.OS, cn.Codename, comp.Component)
				}

				archs := filterAll(mergeArchs(osLayout.Architectures, cn.Architectures, comp.Architectures))
				if len(archs) == 0 {
					return fmt.Errorf("layout %s/%s/%s: architectures are required", osLayout.OS, cn.Codename, comp.Component)
				}

				hashTypes := mergeArchs(osLayout.HashTypes, cn.HashTypes)
				if len(hashTypes) == 0 {
					hashTypes = []string{"sha256"}
				}
				for _, ht := range hashTypes {
					switch ht {
					case "sha256", "sha512", "sha1", "md5sum":
					default:
						return fmt.Errorf("layout %s/%s: invalid hash_type %q (valid: sha256, sha512, sha1, md5sum)", osLayout.OS, cn.Codename, ht)
					}
				}

				var upstreams []model.UpstreamSource
				for _, upName := range comp.Upstreams {
					def, ok := c.Upstreams[upName]
					if !ok {
						return fmt.Errorf("layout %s/%s/%s: unknown upstream %q", osLayout.OS, cn.Codename, comp.Component, upName)
					}

					url := expandPlaceholders(def.URL, osLayout.OS, cn.Codename, comp.Component)

					suite := def.Suite
					if suite == "" {
						suite = "{codename}"
					}
					suite = expandPlaceholders(suite, osLayout.OS, cn.Codename, comp.Component)

					component := def.Component
					if component == "" {
						component = comp.Component
					}
					component = expandPlaceholders(component, osLayout.OS, cn.Codename, comp.Component)

					upArchs := filterAll(def.Architectures)
					if len(upArchs) == 0 {
						upArchs = archs
					}

					upstreams = append(upstreams, model.UpstreamSource{
						Name:         upName,
						URL:          url,
						Suite:        suite,
						Component:    component,
						Archs:        upArchs,
						AutoUpdate:   def.AutoUpdate,
						FetchSources: comp.Sources,
						VerifyKeys:   keyrings[upName],
						Username:     def.Username,
						Password:     expandEnvRef(def.Password),
					})
				}

				resolved = append(resolved, model.Layout{
					OS:        osLayout.OS,
					Codename:  cn.Codename,
					Component: comp.Component,
					Archs:     archs,
					HashTypes: hashTypes,
					Upstreams: upstreams,
				})
			}
		}
	}
	c.ResolvedLayouts = resolved
	return nil
}

// filterAll removes "all" from a list of architectures. arch-independent
// packages are fetched automatically and do not need to be listed explicitly.
func filterAll(archs []string) []string {
	out := archs[:0:0]
	for _, a := range archs {
		if a != "all" {
			out = append(out, a)
		}
	}
	return out
}

func mergeArchs(layers ...[]string) []string {
	for i := len(layers) - 1; i >= 0; i-- {
		if len(layers[i]) > 0 {
			return append([]string(nil), layers[i]...)
		}
	}
	return nil
}

// ComponentsAndArches returns the sorted set of components and architectures
// configured for the given (os, codename) pair.
func (c *Config) ComponentsAndArches(osName, codename string) ([]string, []string) {
	compSet := map[string]bool{}
	archSet := map[string]bool{}
	for _, l := range c.ResolvedLayouts {
		if l.OS != osName || l.Codename != codename {
			continue
		}
		compSet[l.Component] = true
		for _, a := range l.Archs {
			archSet[a] = true
		}
	}
	return sortedKeys(compSet), sortedKeys(archSet)
}

// HashTypesFor returns the configured hash types for the given (os, codename)
// pair. Defaults to ["sha256"] when the pair is not found.
func (c *Config) HashTypesFor(osName, codename string) []string {
	for _, l := range c.ResolvedLayouts {
		if l.OS == osName && l.Codename == codename {
			return l.HashTypes
		}
	}
	return []string{"sha256"}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func expandPlaceholders(s, osName, codename, component string) string {
	r := strings.NewReplacer(
		"{codename}", codename,
		"{component}", component,
		"{os}", osName,
	)
	return r.Replace(s)
}

// expandEnvRef expands a value that is a bare environment variable reference.
// If s starts with "$", the remainder is used as the variable name and its
// value is returned; otherwise s is returned unchanged.
func expandEnvRef(s string) string {
	if strings.HasPrefix(s, "$") {
		return os.Getenv(strings.TrimPrefix(s, "$"))
	}
	return s
}

func loadKeyring(paths []string) (openpgp.EntityList, error) {
	var entities openpgp.EntityList
	for _, p := range paths {
		keys, err := readKeyFile(p)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", p, err)
		}
		entities = append(entities, keys...)
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("no keys loaded from %v", paths)
	}
	return entities, nil
}

// readKeyFile reads an OpenPGP public keyring from path, accepting both
// ASCII-armored (.asc) and binary (.gpg) formats. It tries armored first and
// falls back to binary if the armored parse fails.
func readKeyFile(path string) (openpgp.EntityList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try ASCII-armored first (covers .asc and armored .gpg files).
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err == nil && len(keys) > 0 {
		return keys, nil
	}

	// Fall back to binary packet format.
	keys, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("not a valid armored or binary OpenPGP keyring: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("file contains no OpenPGP keys")
	}
	return keys, nil
}

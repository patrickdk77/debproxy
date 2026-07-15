package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"gopkg.in/yaml.v3"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/webhook"
)

const (
	BackendFilesystem = "filesystem"
	BackendS3         = "s3"

	// NetworkAuto is UpstreamNetwork's default: standard dual-stack dialing
	// (Happy Eyeballs races IPv4/IPv6, using whichever connects first).
	NetworkAuto = ""
	NetworkIPv4 = "ipv4"
	NetworkIPv6 = "ipv6"
)

// Config is the top-level application configuration.
type Config struct {
	LogLevel  string                 `yaml:"log_level"`
	Storage   StorageConfig          `yaml:"storage"`
	UserAgent string                 `yaml:"user_agent"`
	// UpstreamNetwork forces upstream mirror fetches over a specific IP
	// family: "ipv4", "ipv6", or "" (default) for standard dual-stack dialing
	// (Happy Eyeballs races both, using whichever connects first). Set this
	// if one family is broken in your network -- some environments silently
	// black-hole one family (a connection attempt that never completes at
	// all, rather than failing fast), which a connect-time race alone
	// doesn't protect against as reliably as just not attempting it.
	UpstreamNetwork string `yaml:"upstream_network"`
	Webhooks  []webhook.Def          `yaml:"webhooks"`
	Upstreams map[string]UpstreamDef `yaml:"upstreams"`
	Layouts   []OSLayout             `yaml:"layouts"`
	Signing   SigningConfig          `yaml:"signing"`
	Schedule  ScheduleConfig         `yaml:"schedule"`
	Valkey    ValkeyConfig           `yaml:"valkey"`
	// MetricsAddr is the listen address for the Prometheus metrics endpoint
	// (e.g. ":9090"). The endpoint is exposed at /metrics on this address.
	// Leave empty to disable metrics.
	MetricsAddr string `yaml:"metrics_addr"`

	// Auth configures authentication (Basic + OIDC) for the /api HTTP
	// surface. See AuthConfig.
	Auth AuthConfig `yaml:"auth"`
	// API maps resource -> action -> the list of principal globs (Basic
	// usernames and/or OIDC identity/group globs, matched case-insensitively
	// via internal/auth.Match) allowed to call it, e.g.:
	//   api:
	//     snapshot:
	//       create: ["ci-*", "admin"]
	// A resource/action pair with no entry here (or an empty principal list)
	// is not just unauthorized but returns 404 -- see internal/api's request
	// flow doc comment for why. Validated against the fixed resource/action
	// taxonomy by api.New, not here (see the design doc for why this and
	// Auth are validated there instead of in (*Config).validate).
	API map[string]map[string][]string `yaml:"api"`
	// APIJobQueueMax bounds the async admin-operation job queue (update,
	// cleanup, rebuild, prime). Defaults to 1000 when zero -- sized for bulk
	// prime submissions (hundreds of packages at once), not a small cap.
	APIJobQueueMax int `yaml:"api_job_queue_max"`

	ResolvedLayouts []model.Layout `yaml:"-"`
}

// ValkeyConfig configures the optional shared Valkey/Redis cache and
// metadata index. When Enabled, a cluster of debproxy replicas share the
// pool metadata index (instead of each holding it fully in memory) and
// coordinate upstream fetches through Valkey; see the design doc for the
// full architecture. Disabled by default, in which case debproxy behaves
// exactly as it did before this existed (deb822store, no cross-replica
// coordination).
type ValkeyConfig struct {
	Enabled bool `yaml:"enabled"`
	// URL accepts the full grammar of valkey.ParseURL: redis:// or valkey://
	// (rediss:// / valkeys:// for TLS), repeated "?addr=host:port" query
	// params for additional Cluster nodes, and "?master_set=name" for
	// Sentinel. If the password portion starts with "$", it is treated as an
	// environment variable name and expanded at load time, matching
	// UpstreamDef.Password.
	URL string `yaml:"url"`
	// KeyPrefix is prepended to every Valkey key debproxy writes (e.g.
	// "debproxy:"), so a single Valkey deployment can safely be shared with
	// other applications. Empty is valid (no prefix).
	KeyPrefix string `yaml:"key_prefix"`
}

// ScheduleConfig holds all periodic scheduling settings.
type ScheduleConfig struct {
	// Refresh controls how often the server re-fetches upstream package indices
	// in the background. Accepts a Go duration string (e.g. "6h", "12h").
	// Empty string or "0" disables periodic background refreshing.
	Refresh string `yaml:"refresh"`
	// RefreshJitter is the maximum random delay added on top of Refresh on
	// every periodic cycle (each layout draws its own, independently, so
	// they don't stay in lockstep with each other). Accepts a Go duration
	// string (e.g. "5m"). Empty uses the built-in default of 5 minutes; "0"
	// disables jitter entirely (fire exactly every Refresh interval).
	RefreshJitter string `yaml:"refresh_jitter"`
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
	// MetadataFlush controls how often the server persists the metadata index
	// to the storage backend while running in serve mode. Accepts a Go
	// duration string (e.g. "5m", "1h"). "0" disables it entirely. Empty uses
	// a backend-dependent default: 5m for the in-memory deb822store backend
	// (where this just flushes recently-dirty keys, cheap), or 1h when
	// valkey.enabled is true (where it instead pulls the ENTIRE current index
	// out of Valkey and writes it to storage in deb822store's own file
	// format, since Valkey has no separate "dirty" tracking of its own --
	// see metadata.Backuper). This is metadata's only file-based durability
	// when Valkey is enabled; disabling it (or Valkey data loss before the
	// first backup) means recovery falls back to `debproxy rebuild`.
	MetadataFlush string `yaml:"metadata_flush"`
	// SnapshotDebounce is the minimum age the current snapshot must reach
	// before another one is published, whether triggered by this same
	// periodic scheduler or by POST /api/v1/snapshot without
	// {"force": true}. Accepts a Go duration string (e.g. "5m"). Empty uses
	// the built-in default of 5 minutes; "0" disables debouncing entirely.
	SnapshotDebounce string `yaml:"snapshot_debounce"`
}

// RefreshInterval parses Refresh into a time.Duration. Empty, "0", or an
// invalid value all resolve to 0 (disabled) -- this is a lenient runtime
// resolver for callers like avail.Build that need a best-effort duration and
// have no reasonable way to fail a request over a config typo; cmd/debproxy's
// own startup validation of schedule.refresh is separate and stricter (it
// exits on an invalid value rather than silently treating it as disabled).
func (s ScheduleConfig) RefreshInterval() time.Duration {
	if s.Refresh == "" || s.Refresh == "0" {
		return 0
	}
	d, err := time.ParseDuration(s.Refresh)
	if err != nil {
		return 0
	}
	return d
}

// ParseDuration extends time.ParseDuration with a "d" (days) suffix (e.g.
// "30d" == 720h), matching the convention used by schedule.age and other
// pruning-related duration settings. Empty or "0" both parse to zero
// (disabled) -- a meaningful, distinct value from a parse error, which
// callers should still check for separately since a config typo should not
// silently behave like "disabled".
func ParseDuration(s string) (time.Duration, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// ParseSize parses a byte-size config value: a bare number (bytes), or a
// number followed by a case-insensitive "B"/"K"/"KB"/"M"/"MB"/"G"/"GB"
// suffix, using binary (1024-based) multipliers -- the conventional meaning
// for a cache/memory size (as opposed to "d" in ParseDuration, which is
// unambiguous). A fractional number is accepted (e.g. "1.5GB"). Empty or
// "0" both parse to 0 (disabled), a meaningful, distinct value from a parse
// error -- callers should still check for a parse error separately, since a
// config typo should not silently behave like "disabled".
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	upper := strings.ToUpper(s)
	mult := int64(1)
	numPart := upper
	switch {
	case strings.HasSuffix(upper, "GB"), strings.HasSuffix(upper, "G"):
		mult = 1 << 30
		numPart = strings.TrimSuffix(strings.TrimSuffix(upper, "B"), "G")
	case strings.HasSuffix(upper, "MB"), strings.HasSuffix(upper, "M"):
		mult = 1 << 20
		numPart = strings.TrimSuffix(strings.TrimSuffix(upper, "B"), "M")
	case strings.HasSuffix(upper, "KB"), strings.HasSuffix(upper, "K"):
		mult = 1 << 10
		numPart = strings.TrimSuffix(strings.TrimSuffix(upper, "B"), "K")
	case strings.HasSuffix(upper, "B"):
		numPart = strings.TrimSuffix(upper, "B")
	}
	numPart = strings.TrimSpace(numPart)
	n, err := strconv.ParseFloat(numPart, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(n * float64(mult)), nil
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
	Backend     string            `yaml:"backend"`
	Filesystem  FilesystemConfig  `yaml:"filesystem"`
	S3          S3Config          `yaml:"s3"`
	Compression CompressionConfig `yaml:"compression"`
	FileCache   FileCacheConfig   `yaml:"file_cache"`
}

// FileCacheConfig configures an optional in-process LRU cache for pool/src
// file downloads -- the actual .deb/source-archive bytes clients pull
// through -- so repeat requests for a popular file don't re-fetch it from
// the storage backend every time. Most impactful for the S3 backend, where
// every miss is a real GetObject call; harmless but of little value against
// the filesystem backend, which is already local.
type FileCacheConfig struct {
	// Size bounds total cached bytes. Accepts a plain byte count or a
	// number with a KB/MB/GB (binary, 1024-based) suffix, e.g. "500MB",
	// "2GB", "1.5GB" (see ParseSize). Empty or "0" disables the cache
	// entirely -- the default.
	Size string `yaml:"size"`
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
	// UpstreamNetwork overrides the top-level upstream_network for this
	// specific upstream only: "ipv4" or "ipv6". Omit to use the global
	// default. Set this when only one particular mirror has a broken IP
	// family rather than your whole network -- e.g. one ports.ubuntu.com
	// mirror over a flaky IPv6 path, while other upstreams are fine on the
	// default dual-stack behavior.
	UpstreamNetwork string `yaml:"upstream_network"`
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
	cfg.Valkey.URL = expandURLEnvRefs(cfg.Valkey.URL)
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

	switch c.UpstreamNetwork {
	case NetworkAuto, NetworkIPv4, NetworkIPv6:
	default:
		return fmt.Errorf("unknown upstream_network %q (must be \"ipv4\", \"ipv6\", or omitted)", c.UpstreamNetwork)
	}

	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	if len(c.Layouts) == 0 {
		return fmt.Errorf("at least one layout is required")
	}
	if c.Valkey.Enabled && c.Valkey.URL == "" {
		return fmt.Errorf("valkey.url is required when valkey.enabled is true")
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
		switch def.UpstreamNetwork {
		case NetworkAuto, NetworkIPv4, NetworkIPv6:
		default:
			return fmt.Errorf("upstream %q: unknown upstream_network %q (must be \"ipv4\", \"ipv6\", or omitted)", name, def.UpstreamNetwork)
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

					network := def.UpstreamNetwork
					if network == "" {
						network = c.UpstreamNetwork
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
						Network:      network,
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

// expandURLEnvRefs expands any "$VAR" or "${VAR}" references embedded within
// s, unlike expandEnvRef which only handles the whole value being a single
// reference. Used for valkey.url, where a credential is typically embedded
// inside a larger URL (e.g. "valkey://user:$VALKEY_PASSWORD@host:6379/0")
// rather than standing alone.
func expandURLEnvRefs(s string) string {
	return os.Expand(s, os.Getenv)
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

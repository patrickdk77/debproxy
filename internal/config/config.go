package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"gopkg.in/yaml.v3"

	"github.com/debproxy/debproxy/internal/model"
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
	// RefreshInterval controls how often the server re-fetches upstream package
	// indices in the background. Accepts a Go duration string (e.g. "6h", "12h").
	// Empty string or "0" disables periodic background refreshing.
	RefreshInterval  string `yaml:"refresh_interval"`
	// SnapshotSchedule controls when the server automatically publishes snapshots
	// while running in serve mode. Three formats are accepted:
	//   "daily@HH:MM"          — every day at a fixed UTC time (e.g. "daily@03:00")
	//   "weekly@day@HH:MM"     — every week on a fixed UTC day/time (e.g. "weekly@sunday@03:00")
	//   Go duration string     — every N hours/minutes with jitter (e.g. "24h")
	// Empty string or "0" disables automatic snapshots.
	SnapshotSchedule string `yaml:"snapshot_schedule"`
	// MaxSnapshots is the maximum number of snapshots to retain. A snapshot is
	// only deleted when BOTH MaxSnapshots and MaxSnapshotAge are exceeded.
	// 0 disables count-based pruning.
	MaxSnapshots int `yaml:"max_snapshots"`
	// MaxSnapshotAge is the maximum age of a snapshot before it becomes eligible
	// for deletion. Accepts a Go duration string with optional "d" suffix for days
	// (e.g. "90d", "720h"). A snapshot is only deleted when BOTH MaxSnapshots and
	// MaxSnapshotAge are exceeded. Empty string or "0" disables age-based pruning.
	MaxSnapshotAge string `yaml:"max_snapshot_age"`
	// CleanupSchedule controls when the server automatically runs snapshot pruning
	// and pool GC while in serve mode. Accepts the same format as SnapshotSchedule.
	// Empty string or "0" disables automatic cleanup.
	CleanupSchedule string `yaml:"cleanup_schedule"`

	ResolvedLayouts []model.Layout `yaml:"-"`
}

type StorageConfig struct {
	Backend    string           `yaml:"backend"`
	Filesystem FilesystemConfig `yaml:"filesystem"`
	S3         S3Config         `yaml:"s3"`
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
	Codenames     []CodenameLayout `yaml:"codenames"`
}

type CodenameLayout struct {
	Codename      string            `yaml:"codename"`
	Architectures []string          `yaml:"architectures"`
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

				archs := mergeArchs(osLayout.Architectures, cn.Architectures, comp.Architectures)
				if len(archs) == 0 {
					return fmt.Errorf("layout %s/%s/%s: architectures are required", osLayout.OS, cn.Codename, comp.Component)
				}

				var upstreams []model.UpstreamSource
				for _, upName := range comp.Upstreams {
					def, ok := c.Upstreams[upName]
					if !ok {
						return fmt.Errorf("layout %s/%s/%s: unknown upstream %q", osLayout.OS, cn.Codename, comp.Component, upName)
					}

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

					upArchs := def.Architectures
					if len(upArchs) == 0 {
						upArchs = archs
					}

					upstreams = append(upstreams, model.UpstreamSource{
						Name:         upName,
						URL:          def.URL,
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
					Upstreams: upstreams,
				})
			}
		}
	}
	c.ResolvedLayouts = resolved
	return nil
}

func mergeArchs(layers ...[]string) []string {
	for i := len(layers) - 1; i >= 0; i-- {
		if len(layers[i]) > 0 {
			return append([]string(nil), layers[i]...)
		}
	}
	return nil
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

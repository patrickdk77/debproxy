package main

import (
	"context"
	"flag"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/api"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadatafactory"
	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/rebuild"
	"github.com/debproxy/debproxy/internal/safego"
	"github.com/debproxy/debproxy/internal/server"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/filecache"
	"github.com/debproxy/debproxy/internal/storagefactory"
	syncerpkg "github.com/debproxy/debproxy/internal/syncer"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
	"github.com/debproxy/debproxy/internal/webhook"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "rebuild":
		os.Exit(runRebuild(os.Args[2:]))
	case "update":
		os.Exit(runUpdate(os.Args[2:]))
	case "snapshot":
		os.Exit(runSnapshot(os.Args[2:]))
	case "prime":
		os.Exit(runPrime(os.Args[2:]))
	case "publish-key":
		os.Exit(runPublishKey(os.Args[2:]))
	case "cleanup":
		os.Exit(runCleanup(os.Args[2:]))
	case "healthcheck":
		os.Exit(runHealthcheck(os.Args[2:]))
	case "version":
		os.Exit(runVersion())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	addr := fs.String("addr", "http://localhost:8080", "base URL of the running server")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resp, err := http.Get(*addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unhealthy: %s\n", resp.Status)
		return 1
	}
	return 0
}

func runVersion() int {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Println("unknown")
		return 1
	}
	commit, dirty := "unknown", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	fmt.Printf("%s%s\n", commit, dirty)
	return 0
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  debproxy serve [--config path] [--addr :8080]
  debproxy rebuild [--config path] [--reset=false]   (--reset defaults to true: truncates the index before rebuild)
  debproxy update [--config path]
  debproxy snapshot [--config path]
  debproxy cleanup [--config path]
  debproxy prime [--config path] --os debian --codename trixie --component main --pkg name[,name...]
  debproxy publish-key [--config path]
  debproxy healthcheck [--addr http://localhost:8080]
  debproxy version
`)
}

func loadConfig(args []string) (*config.Config, error) {
	fs := flag.NewFlagSet("cmd", flag.ExitOnError)
	configPath := fs.String("config", "config.example.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*configPath)
}

// withTimeout10s runs fn with a fresh 10-second timeout, distinct from
// whatever budget any other call in the same sequence got.
func withTimeout10s(fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return fn(ctx)
}

// defaultLockTTL / defaultLockRenewInterval configure the distributed
// upstream-fetch lock. Deliberately not configurable: renew_interval must
// stay meaningfully smaller than TTL for the "renew while a fetch is in
// flight" mechanism to do anything, and a bad pair would fail silently (the
// lock would just expire before ever being renewed, with nothing to notice
// or warn) -- not a knob worth the risk of misconfiguration.
const (
	defaultLockTTL           = 2 * time.Minute
	defaultLockRenewInterval = 30 * time.Second
)

// schedulerLockWait bounds how long the periodic snapshot/cleanup
// schedulers wait for api.OpLock before skipping this cycle -- short and
// non-blocking-in-spirit, matching api.snapshotLockWait's own reasoning:
// these are background ticks, not a request a caller is waiting on, but
// there's no reason to give up faster than a request would.
const schedulerLockWait = 5 * time.Second

// Defaults for schedule.metadata_flush; see ScheduleConfig.MetadataFlush.
// The Valkey default is longer because a Backuper pulls the entire current
// index on every save rather than just recently-dirty keys.
const (
	defaultMetadataFlushInterval       = 5 * time.Minute
	defaultMetadataFlushIntervalValkey = time.Hour
)

// resolveMetadataFlushInterval resolves schedule.metadata_flush. "0" here is
// a meaningful, distinct value (explicitly disable periodic metadata
// persistence) rather than "unset".
func resolveMetadataFlushInterval(cfg *config.Config) time.Duration {
	def := defaultMetadataFlushInterval
	if cfg.Valkey.Enabled {
		def = defaultMetadataFlushIntervalValkey
	}
	raw := cfg.Schedule.MetadataFlush
	if raw == "" {
		return def
	}
	if raw == "0" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid schedule.metadata_flush, using default", "value", raw, "default", def, "err", err)
		return def
	}
	return d
}

// Default for schedule.refresh_jitter; see ScheduleConfig.RefreshJitter.
const defaultRefreshJitter = 5 * time.Minute

// resolveRefreshJitter resolves schedule.refresh_jitter. "0" here is a
// meaningful, distinct value (disable jitter entirely) rather than "unset".
func resolveRefreshJitter(cfg *config.Config) time.Duration {
	raw := cfg.Schedule.RefreshJitter
	if raw == "" {
		return defaultRefreshJitter
	}
	if raw == "0" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid schedule.refresh_jitter, using default", "value", raw, "default", defaultRefreshJitter, "err", err)
		return defaultRefreshJitter
	}
	return d
}

// Default for schedule.snapshot_debounce; see ScheduleConfig.SnapshotDebounce.
const defaultSnapshotDebounce = 5 * time.Minute

// resolveSnapshotDebounce resolves schedule.snapshot_debounce. "0" here is a
// meaningful, distinct value (disable debouncing entirely) rather than
// "unset".
func resolveSnapshotDebounce(cfg *config.Config) time.Duration {
	raw := cfg.Schedule.SnapshotDebounce
	if raw == "" {
		return defaultSnapshotDebounce
	}
	if raw == "0" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid schedule.snapshot_debounce, using default", "value", raw, "default", defaultSnapshotDebounce, "err", err)
		return defaultSnapshotDebounce
	}
	return d
}

func openBackends(ctx context.Context, cfg *config.Config) (storage.Storage, metadata.MetadataIndex, error) {
	store, err := storagefactory.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	index, err := metadatafactory.New(ctx, store, cfg)
	if err != nil {
		return nil, nil, err
	}
	return store, index, nil
}

func runRebuild(args []string) int {
	fs := flag.NewFlagSet("rebuild", flag.ExitOnError)
	configPath := fs.String("config", "config.example.yaml", "path to config file")
	reset := fs.Bool("reset", true, "truncate index before rebuild")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	store, index, err := openBackends(context.Background(), cfg)
	if err != nil {
		slog.Error("open backends", "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		slog.Info("interrupted, flushing index")
		if err := index.Flush(context.Background()); err != nil {
			slog.Error("flush index on interrupt", "err", err)
		}
		os.Exit(1)
	}()

	if err := rebuild.Run(ctx, cfg, store, index, rebuild.Options{ResetIndex: *reset, HTTPClient: upstream.NewHTTPClient(cfg.UserAgent)}); err != nil {
		slog.Error("rebuild", "err", err)
		return 1
	}
	if err := index.Flush(ctx); err != nil {
		slog.Error("flush index", "err", err)
		return 1
	}
	return 0
}

func buildNotifier(cfg *config.Config) (*webhook.Notifier, error) {
	return webhook.New(cfg.Webhooks, nil)
}

// loadKey loads the configured signing key. Every caller requires a working
// key, so a missing/unconfigured key is itself an error -- callers don't need
// to separately check for a nil key.
func loadKey(cfg *config.Config) (*signing.Key, error) {
	if cfg.Signing.PrivateKey == "" {
		return nil, fmt.Errorf("signing.private_key is not configured")
	}
	return signing.Load(cfg.Signing.PrivateKey)
}

func runUpdate(args []string) int {
	cfg, err := loadConfig(args)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	store, index, err := openBackends(context.Background(), cfg)
	if err != nil {
		slog.Error("open backends", "err", err)
		return 1
	}
	key, err := loadKey(cfg)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return 1
	}
	notifier, err := buildNotifier(cfg)
	if err != nil {
		slog.Error("webhook config", "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	s := syncerpkg.New(cfg, store, index, key, upstream.NewHTTPClient(cfg.UserAgent), nil, notifier)
	if err := s.PreloadExistsCache(ctx); err != nil {
		slog.Warn("preload pool exists cache", "err", err)
	}
	if err := s.Update(ctx); err != nil {
		slog.Error("update", "err", err)
		return 1
	}
	if err := index.Flush(ctx); err != nil {
		slog.Error("flush index after update", "err", err)
		return 1
	}
	snapNow := time.Now()
	if err := s.Snapshot(ctx, snapNow); err != nil {
		slog.Error("snapshot after update", "err", err)
		return 1
	}
	writeSnapshotName(snapNow.UTC().Format(syncerpkg.SnapshotIDFormat))
	slog.Info("update complete")
	return 0
}

func runSnapshot(args []string) int {
	cfg, err := loadConfig(args)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	store, index, err := openBackends(context.Background(), cfg)
	if err != nil {
		slog.Error("open backends", "err", err)
		return 1
	}
	key, err := loadKey(cfg)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	s := syncerpkg.New(cfg, store, index, key, upstream.NewHTTPClient(cfg.UserAgent), nil, nil)
	snapNow := time.Now()
	if err := s.Snapshot(ctx, snapNow); err != nil {
		slog.Error("snapshot", "err", err)
		return 1
	}
	writeSnapshotName(snapNow.UTC().Format(syncerpkg.SnapshotIDFormat))
	slog.Info("snapshot complete")
	return 0
}

func runCleanup(args []string) int {
	cfg, err := loadConfig(args)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	store, index, err := openBackends(context.Background(), cfg)
	if err != nil {
		slog.Error("open backends", "err", err)
		return 1
	}
	key, err := loadKey(cfg)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return 1
	}
	maxAge, err := config.ParseDuration(cfg.Schedule.Age)
	if err != nil {
		slog.Error("invalid schedule.age", "value", cfg.Schedule.Age, "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	s := syncerpkg.New(cfg, store, index, key, upstream.NewHTTPClient(cfg.UserAgent), nil, nil)
	if err := s.Cleanup(ctx, cfg.Schedule.History, maxAge, time.Now()); err != nil {
		slog.Error("cleanup", "err", err)
		return 1
	}
	if err := index.Flush(ctx); err != nil {
		slog.Error("flush index", "err", err)
		return 1
	}
	slog.Info("cleanup complete")
	return 0
}

func runPrime(args []string) int {
	fs := flag.NewFlagSet("prime", flag.ExitOnError)
	configPath := fs.String("config", "config.example.yaml", "path to config file")
	osName := fs.String("os", "", "operating system (e.g. debian)")
	codename := fs.String("codename", "", "codename (e.g. trixie)")
	component := fs.String("component", "main", "component (e.g. main)")
	pkgs := fs.String("pkg", "", "comma-separated package names to seed")
	snapshot := fs.Bool("snapshot", true, "publish a snapshot after priming")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *osName == "" || *codename == "" || *pkgs == "" {
		slog.Error("prime requires --os, --codename, and --pkg")
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	store, index, err := openBackends(context.Background(), cfg)
	if err != nil {
		slog.Error("open backends", "err", err)
		return 1
	}
	key, err := loadKey(cfg)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return 1
	}
	notifier, err := buildNotifier(cfg)
	if err != nil {
		slog.Error("webhook config", "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()
	s := syncerpkg.New(cfg, store, index, key, upstream.NewHTTPClient(cfg.UserAgent), nil, notifier)
	if err := s.PreloadExistsCache(ctx); err != nil {
		slog.Warn("preload pool exists cache", "err", err)
	}
	names := splitCSV(*pkgs)
	if err := s.Prime(ctx, *osName, *codename, *component, names); err != nil {
		slog.Error("prime", "err", err)
		return 1
	}
	slog.Info("prime complete", "packages", names)
	if err := index.Flush(ctx); err != nil {
		slog.Error("flush index after prime", "err", err)
		return 1
	}
	if *snapshot {
		snapNow := time.Now()
		if err := s.Snapshot(ctx, snapNow); err != nil {
			slog.Error("snapshot", "err", err)
			return 1
		}
		writeSnapshotName(snapNow.UTC().Format(syncerpkg.SnapshotIDFormat))
	}
	return 0
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runPublishKey(args []string) int {
	fs := flag.NewFlagSet("publish-key", flag.ExitOnError)
	configPath := fs.String("config", "config.example.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	if cfg.Signing.PrivateKey == "" {
		slog.Error("signing.private_key is not configured")
		return 1
	}
	store, err := storagefactory.New(cfg)
	if err != nil {
		slog.Error("open storage", "err", err)
		return 1
	}
	key, err := signing.Load(cfg.Signing.PrivateKey)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	names, err := key.Publish(ctx, store)
	if err != nil {
		slog.Error("publish signing public key", "err", err)
		return 1
	}
	slog.Info("published signing public key", "fingerprint", key.Fingerprint(), "key_id", key.KeyID(), "files", names)
	return 0
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "config.example.yaml", "path to config file")
	addr := fs.String("addr", ":8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		return 1
	}
	store, index, err := openBackends(context.Background(), cfg)
	if err != nil {
		slog.Error("open backends", "err", err)
		return 1
	}

	// Each startup check gets its own fresh timeout rather than sharing one
	// budget, so a slow-but-healthy backend can't make a later check fail
	// just because an earlier one ate most of the deadline.
	if err := withTimeout10s(store.Ping); err != nil {
		slog.Error("storage ping", "err", err)
		return 1
	}
	if err := withTimeout10s(index.Ping); err != nil {
		slog.Error("metadata ping", "err", err)
		return 1
	}

	key, err := loadKey(cfg)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return 1
	}
	fpPath := path.Join(signing.KeysDir, key.Fingerprint()+".asc")

	statErr := withTimeout10s(func(ctx context.Context) error {
		_, err := store.StatPublished(ctx, fpPath)
		return err
	})
	if statErr != nil && !os.IsNotExist(statErr) {
		slog.Error("check signing key", "err", statErr)
		return 1
	}
	if os.IsNotExist(statErr) {
		var names []string
		pubErr := withTimeout10s(func(ctx context.Context) error {
			var err error
			names, err = key.Publish(ctx, store)
			return err
		})
		if pubErr != nil {
			slog.Error("publish signing public key", "err", pubErr)
			return 1
		}
		slog.Info("published signing public key", "fingerprint", key.Fingerprint(), "files", names)
	} else {
		slog.Debug("signing key already published", "fingerprint", key.Fingerprint())
	}

	httpClient := upstream.NewHTTPClient(cfg.UserAgent)
	indexCache := upstream.NewIndexCache()

	// vclient is shared between the upstream fetch cache/lock (below) and the
	// /live serving-artifact cache (wired into server.New's result further
	// down) -- one shared client for the whole process rather than a second
	// connection, since valkey-go's Client is safe for concurrent use.
	var vclient valkey.Client
	if cfg.Valkey.Enabled {
		var err error
		vclient, err = valkeycache.NewClient(cfg.Valkey.URL)
		if err != nil {
			slog.Error("connect to valkey", "err", err)
			return 1
		}
		indexCache.EnableValkey(vclient, valkeycache.Keys{Prefix: cfg.Valkey.KeyPrefix}, defaultLockTTL, defaultLockRenewInterval)
	}

	notifier, err := buildNotifier(cfg)
	if err != nil {
		slog.Error("webhook config", "err", err)
		return 1
	}

	var refreshInterval time.Duration
	if cfg.Schedule.Refresh != "" && cfg.Schedule.Refresh != "0" {
		d, err := time.ParseDuration(cfg.Schedule.Refresh)
		if err != nil {
			slog.Error("invalid schedule.refresh", "value", cfg.Schedule.Refresh, "err", err)
			return 1
		}
		refreshInterval = d
	}

	snapSched, err := parseSnapshotSchedule(cfg.Schedule.Snapshot)
	if err != nil {
		slog.Error("invalid schedule.snapshot", "value", cfg.Schedule.Snapshot, "err", err)
		return 1
	}
	cleanupSched, err := parseSnapshotSchedule(cfg.Schedule.Cleanup)
	if err != nil {
		slog.Error("invalid schedule.cleanup", "value", cfg.Schedule.Cleanup, "err", err)
		return 1
	}
	if _, err := config.ParseDuration(cfg.Schedule.Age); err != nil {
		slog.Error("invalid schedule.age", "value", cfg.Schedule.Age, "err", err)
		return 1
	}

	syncr := syncerpkg.New(cfg, store, index, key, httpClient, indexCache, notifier)
	if err := syncr.PreloadExistsCache(context.Background()); err != nil {
		slog.Warn("preload pool exists cache", "err", err)
	}

	// Persist metadata periodically either way -- losing everything since the
	// last save on a crash is not acceptable for either backend. A
	// Backuper-backed index (valkeystore) saves per layout grouping, per
	// component, as each finishes its own refresh cycle (see
	// saveLayoutMetadata, wired into startIndexRefresher below), so it needs
	// no separate ticker here. Any other index (deb822store) keeps its
	// original periodic Flush ticker (startPeriodicMetadataFlush), unchanged.
	// On graceful shutdown that ticker's stop func does one final save.
	// SIGKILL cannot be caught; the interval bounds how much is lost in that
	// case (the index can also be rebuilt with `debproxy rebuild`).
	metadataFlushInterval := resolveMetadataFlushInterval(cfg)
	stopFlush := startPeriodicMetadataFlush(index, metadataFlushInterval)
	stopMerge := startPeriodicMerge(index, time.Hour)
	stopRefresher := startIndexRefresher(cfg, refreshDeps{
		client:        httpClient,
		cache:         indexCache,
		syncr:         syncr,
		index:         index,
		store:         store,
		interval:      refreshInterval,
		jitter:        resolveRefreshJitter(cfg),
		flushInterval: metadataFlushInterval,
		vclient:       vclient,
		vkeys:         valkeycache.Keys{Prefix: cfg.Valkey.KeyPrefix},
	})
	vkeys := valkeycache.Keys{Prefix: cfg.Valkey.KeyPrefix}
	// oplock serializes debproxy's mutating admin operations -- snapshot,
	// cleanup, update, rebuild, prime -- against each other, whether
	// triggered by these periodic schedulers or by the /api surface below,
	// and (when Valkey is enabled) across every replica. One instance is
	// shared between both consumers: constructing two separate OpLocks over
	// the no-Valkey fallback would each get their own, non-communicating
	// in-process channel, defeating the exclusion entirely.
	oplock := api.NewOpLock(vclient, vkeys)
	snapshotDebounce := resolveSnapshotDebounce(cfg)

	stopSnapshotter := startPeriodicSnapshot(syncr, snapSched, oplock, indexCache, snapshotDebounce, vclient)
	stopCleaner := startPeriodicCleanup(syncr, cleanupSched, cfg, oplock)

	if cfg.MetricsAddr != "" {
		metricsSrv := &http.Server{Addr: cfg.MetricsAddr, Handler: promhttp.Handler()}
		go func() {
			slog.Info("metrics listening", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics serve", "err", err)
			}
		}()
	}

	webServer := server.New(cfg, store, index, key, httpClient, indexCache, notifier, syncr.ExistsCache())
	stopLiveValkey := func() {}
	if cfg.Valkey.Enabled {
		stopLiveValkey = webServer.EnableValkey(context.Background(), vclient, *addr)
	}

	// If storage.file_cache.size is configured, store is a *filecache.Store
	// (see storagefactory.New) and needs to purge its "current/" entries
	// whenever ANOTHER replica publishes a snapshot -- this replica's own
	// snapshot publishes already self-invalidate via filecache.Store's
	// WriteFile override, so this subscriber exists purely for that
	// cross-replica case. A no-op when Valkey is disabled (nothing to
	// subscribe to) or the file cache is disabled (store doesn't implement
	// filecache.Purger, so the type assertion below just skips it).
	stopSnapshotPurgeSubscriber := func() {}
	if cfg.Valkey.Enabled {
		if purger, ok := store.(filecache.Purger); ok {
			subCtx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			safego.Go("snapshot-published subscriber", func() {
				defer close(done)
				valkeycache.Subscribe(subCtx, vclient, valkeycache.ChannelSnapshotPublished, func(valkey.PubSubMessage) {
					safego.Run("snapshot-published purge", func() { purger.PurgePrefix("current/") })
				})
			})
			stopSnapshotPurgeSubscriber = func() { cancel(); <-done }
		}
	}

	apiSrv, err := api.New(api.Deps{
		Config:           cfg,
		Store:            store,
		Index:            index,
		Syncer:           syncr,
		IndexCache:       indexCache,
		HTTPClient:       httpClient,
		Key:              key,
		OpLock:           oplock,
		VClient:          vclient,
		VKeys:            vkeys,
		Notifier:         notifier,
		SnapshotDebounce: snapshotDebounce,
	})
	if err != nil {
		slog.Error("api config", "err", err)
		return 1
	}

	// /api/ is matched ahead of "/" by net/http's ServeMux (the more specific
	// pattern wins), so apiSrv.Handler() -- which itself does its own
	// resource/action/permission routing under /api/v1/... -- sees every
	// request under /api/, and webServer.Handler() sees everything else,
	// unchanged from before this feature existed.
	topMux := http.NewServeMux()
	topMux.Handle("/api/", apiSrv.Handler())
	topMux.Handle("/", webServer.Handler())

	srv := &http.Server{Addr: *addr, Handler: topMux}
	go func() {
		slog.Info("listening", "addr", *addr, "layouts", len(cfg.ResolvedLayouts))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	slog.Info("shutting down")

	// Drain in-flight requests before the final metadata flush so no handler
	// can write to the index after we flush.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown", "err", err)
	}

	stopLiveValkey()
	stopSnapshotPurgeSubscriber()
	// Stops intake and waits for any in-flight async job to finish; queued
	// jobs behind it are abandoned but re-triggerable (see operationRunner's
	// own doc comment) -- called before the scheduler/refresher stops below
	// since they share apiSrv's operation lock, not because ordering among
	// them matters for correctness.
	apiSrv.Close()
	stopRefresher()
	stopSnapshotter()
	stopCleaner()
	stopMerge()
	stopFlush()
	return 0
}

// layoutKey identifies one (os, codename) layout grouping -- a downstream
// repository view, per model.Layout's own doc comment -- for scheduling
// purposes.
type layoutKey struct{ os, codename string }

// layoutUpstreamGroups collects every layout's upstreams per (os, codename),
// in config order, matching Syncer.layoutsByOSCodename's own grouping.
func layoutUpstreamGroups(cfg *config.Config) (keys []layoutKey, byKey map[layoutKey][]model.UpstreamSource) {
	byKey = map[layoutKey][]model.UpstreamSource{}
	for _, layout := range cfg.ResolvedLayouts {
		k := layoutKey{layout.OS, layout.Codename}
		if _, exists := byKey[k]; !exists {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], layout.Upstreams...)
	}
	return keys, byKey
}

// layoutSeedOffset returns a deterministic offset within [0, interval) for
// key, derived from a hash of its own identity. The same layout always gets
// the same offset -- stable across restarts, and identical across every
// replica running the same config -- while different layouts land at
// well-distributed points across the interval. This is what lets each
// layout's refresh schedule drift apart from the others instead of all
// firing in one synchronized burst every cycle: in a multi-replica
// deployment, that burst would otherwise mean every replica hammering every
// upstream's fetch lock at the same few moments, rather than spreading lock
// contention and upstream load out continuously. It also makes it possible
// to reason about a Valkey freshness TTL relative to one layout's own,
// predictable cadence instead of a shared global one.
func layoutSeedOffset(key layoutKey, interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key.os + "/" + key.codename))
	return time.Duration(h.Sum64() % uint64(interval))
}

// refreshDeps bundles the dependencies shared by startIndexRefresher and
// every function it calls into for one layout's refresh cycle
// (runLayoutRefreshLoop/refreshLayoutGroup/saveLayoutMetadata), so adding a
// new shared dependency doesn't require editing every signature in the
// chain. key/upstreams stay separate function parameters since they vary
// per call, not per refresher.
type refreshDeps struct {
	client        *http.Client
	cache         *upstream.IndexCache
	syncr         *syncerpkg.Syncer
	index         metadata.MetadataIndex
	store         storage.Storage
	interval      time.Duration
	jitter        time.Duration
	flushInterval time.Duration
	tracker       *layoutSaveTracker
	vclient       valkey.Client
	vkeys         valkeycache.Keys
}

// startIndexRefresher spins up one independent refresh goroutine per
// (os, codename) layout grouping (see layoutKey), each pre-warming its own
// upstream index cache shortly after startup and then re-fetching every
// interval (if > 0). After each refresh it calls
// syncr.UpdateLayoutWithCache to pull any newer auto_update packages for
// just that layout. Each goroutine's initial delay is 2 minutes, plus up to
// 60 seconds of shared startup jitter, plus that layout's own deterministic
// seed offset (see layoutSeedOffset) so layouts don't all fire together.
// Each periodic refresh after that adds up to jitter (see
// resolveRefreshJitter) of random delay, same as before this was split per
// layout.
//
// Independent schedules mean two layouts' fetch/update/GC cycles could land
// at the same moment by chance (or drift into alignment over time, since
// each cycle's jitter is redrawn independently). cache.Lock/Unlock (see
// upstream.IndexCache) ensures only one layout's cycle actually runs at a
// time -- and, since /live request handling in internal/server builds
// through this same cache, also that a live request's own build never runs
// concurrently with this refresher's -- restoring the same "one at a time,
// GC in between" bound on peak allocation the old strictly-sequential loop
// had, while still letting each layout's own timer fire independently
// rather than gating on a global clock.
//
// Returns a stop function that cancels every layout's in-progress refresh
// and waits for all of them to finish.
func startIndexRefresher(cfg *config.Config, deps refreshDeps) func() {
	keys, byKey := layoutUpstreamGroups(cfg)
	deps.tracker = &layoutSaveTracker{client: deps.vclient, keys: deps.vkeys}
	stop := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Add(1)
		k := k
		go func() {
			defer wg.Done()
			runLayoutRefreshLoop(stop, k, byKey[k], deps)
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return func() {
		close(stop)
		<-done
	}
}

// runLayoutRefreshLoop is one layout grouping's independent refresh
// schedule; see startIndexRefresher.
func runLayoutRefreshLoop(stop <-chan struct{}, key layoutKey, upstreams []model.UpstreamSource, deps refreshDeps) {
	startupJitter := time.Duration(rand.Intn(61)) * time.Second
	initialDelay := 2*time.Minute + startupJitter + layoutSeedOffset(key, deps.interval)
	select {
	case <-time.After(initialDelay):
	case <-stop:
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-stop; cancel() }()

	runRefreshLocked := func() {
		// Wrapped in safego.Run so a panic during one layout's refresh cycle
		// (upstream fetch/parse, auto-update, metadata save) is logged and
		// contained to this cycle -- the loop keeps running and retries next
		// interval -- instead of silently ending this layout's refresh
		// goroutine forever (or, before safego existed anywhere in this
		// codebase, crashing the whole process).
		safego.Run(fmt.Sprintf("layout refresh %s/%s", key.os, key.codename), func() {
			// Every replica's own local timer fires independently, but only one
			// of them should actually do the work each interval -- claim it
			// first (see valkeycache.Keys.RefreshClaim). If another replica
			// already refreshed this layout within the current interval, its
			// claim is still held and this attempt fails cleanly (no error): skip
			// entirely rather than redundantly repeating the same upstream
			// fetches and auto-update pulls. A real error acquiring the claim
			// (e.g. Valkey unreachable) fails open -- refresh directly rather
			// than silently skipping a layout because coordination is down.
			if deps.vclient != nil && deps.interval > 0 {
				_, claimed, err := valkeycache.AcquireLock(ctx, deps.vclient, deps.vkeys.RefreshClaim(key.os, key.codename), deps.interval)
				if err != nil {
					slog.Warn("valkey refresh claim unavailable, refreshing directly", "os", key.os, "codename", key.codename, "err", err)
				} else if !claimed {
					slog.Debug("layout already refreshed by another replica this interval, skipping", "os", key.os, "codename", key.codename)
					return
				}
			}
			deps.cache.Lock()
			defer deps.cache.Unlock()
			refreshLayoutGroup(ctx, key, upstreams, deps)
		})
	}

	runRefreshLocked()
	if deps.interval > 0 {
		for {
			cycleJitter := valkeycache.RandDuration(deps.jitter)
			select {
			case <-time.After(deps.interval + cycleJitter):
				runRefreshLocked()
			case <-stop:
				return
			}
		}
	}

	// schedule.refresh is disabled for this layout: upstream indexes are
	// never re-fetched again after the one run above, but the pool can still
	// change independently (on-demand pull-through), so a Backuper-backed
	// index (valkeystore) still needs its own periodic save on
	// schedule.metadata_flush's own cadence. deb822store already gets one
	// from its own ticker regardless of schedule.refresh (see
	// startPeriodicMetadataFlush), so this loop is specifically for the
	// Backuper case.
	if _, ok := deps.index.(metadata.Backuper); !ok || deps.flushInterval <= 0 {
		return
	}
	saveOnlyLocked := func() {
		safego.Run(fmt.Sprintf("layout metadata save %s/%s", key.os, key.codename), func() {
			deps.cache.Lock()
			defer deps.cache.Unlock()
			if ctx.Err() != nil {
				return
			}
			saveLayoutMetadata(ctx, key, upstreams, deps)
		})
	}
	for {
		select {
		case <-time.After(deps.flushInterval + valkeycache.RandDuration(deps.jitter)):
			saveOnlyLocked()
		case <-stop:
			return
		}
	}
}

// refreshLayoutGroup fetches every upstream index feeding one (os, codename)
// layout grouping into the cache concurrently (upstreams deduplicated by
// URL/suite/component, since the same upstream mirror can back multiple
// components, then fetched in parallel the same way avail.Build fetches a
// layout's upstreams), then runs the auto-update check scoped to just that
// layout, then saves that layout's own slice of the metadata index (see
// saveLayoutMetadata), then frees whatever that pass allocated.
func refreshLayoutGroup(ctx context.Context, key layoutKey, upstreams []model.UpstreamSource, deps refreshDeps) {
	if ctx.Err() != nil {
		return
	}
	seen := map[string]bool{}
	var uniq []model.UpstreamSource
	for _, src := range upstreams {
		srcKey := src.DedupKey()
		if seen[srcKey] {
			continue
		}
		seen[srcKey] = true
		uniq = append(uniq, src)
	}

	fetchers := make([]*upstream.Fetcher, len(uniq))
	var wg sync.WaitGroup
	for i, src := range uniq {
		wg.Add(1)
		go func(i int, src model.UpstreamSource) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			slog.Info("refreshing upstream index", "os", key.os, "codename", key.codename, "upstream", src.Name, "suite", src.Suite, "component", src.Component)
			f := upstream.NewFetcherWithCache(src, deps.client, deps.cache)
			fetchers[i] = f
			if _, err := f.FetchIndex(ctx); err != nil {
				slog.Warn("upstream index refresh failed", "upstream", src.Name, "suite", src.Suite, "component", src.Component, "err", err)
			}
		}(i, src)
	}
	wg.Wait()
	if ctx.Err() != nil {
		debug.FreeOSMemory()
		return
	}
	slog.Info("upstream index refresh complete", "os", key.os, "codename", key.codename, "sources", len(uniq))

	if err := deps.syncr.UpdateLayoutWithCache(ctx, deps.cache, key.os, key.codename); err != nil {
		slog.Warn("post-refresh update failed", "os", key.os, "codename", key.codename, "err", err)
	}
	if ctx.Err() == nil {
		saveLayoutMetadata(ctx, key, upstreams, deps)
	}
	// Evict this cycle's fetched upstream data from the local cache now that
	// this layout is done using it (auto-update check and metadata save both
	// already ran above) -- a no-op unless cache is Valkey-backed, in which
	// case Valkey remains the durable copy and the next cycle (here or via a
	// live request elsewhere) re-adopts fresh or comparison data from it (see
	// IndexCache.EvictUpstream) rather than this process holding every
	// layout's Packages/Sources resident for its entire lifetime.
	for _, f := range fetchers {
		deps.cache.EvictUpstream(f.InReleaseURL(), f.Component())
	}
	// Marking the layout freshly synced (see upstream.IndexCache.
	// MarkLayoutDataFresh) is avail.Build's own responsibility, not this
	// function's: UpdateLayoutWithCache above calls avail.Build internally,
	// which already marks freshness itself, correctly gated on both the
	// Index *and* Sources fetches it does succeeding -- this loop only
	// fetches Index data and only pre-warms the cache so avail.Build's own
	// per-upstream fetches (which don't dedupe shared upstreams across this
	// layout's components the way the loop above does) hit the fast path
	// instead of re-fetching. Marking fresh here too, gated only on this
	// loop's own Index-only success, would let a real Sources failure
	// elsewhere in the same cycle go unnoticed.
	debug.FreeOSMemory()
}

// writeSnapshotName records the snapshot ID in a file named "snapshot-name" in
// the current working directory so that copies or clones of this installation
// can identify which snapshot they were made from.
func writeSnapshotName(id string) {
	if err := os.WriteFile("snapshot-name", []byte(id+"\n"), 0644); err != nil {
		slog.Warn("write snapshot-name file", "err", err)
	}
}

// snapshotSched holds a parsed schedule.snapshot or schedule.cleanup value.
type snapshotSched struct {
	kind    string        // "interval", "daily", "weekly"
	d       time.Duration // interval mode
	hour    int           // daily/weekly: UTC hour
	minute  int           // daily/weekly: UTC minute
	weekday time.Weekday  // weekly only
}

// parseSnapshotSchedule parses a schedule.snapshot or schedule.cleanup value. Accepted forms:
//
//	"daily@HH:MM"       every day at a fixed UTC time (e.g. "daily@03:00")
//	"sunday@HH:MM"      every Sunday at a fixed UTC time (any weekday name works)
//	Go duration string  interval with up to 5 minutes of jitter (e.g. "24h")
//	"" or "0"           disabled
func parseSnapshotSchedule(s string) (snapshotSched, error) {
	if s == "" || s == "0" {
		return snapshotSched{}, nil
	}
	lower := strings.ToLower(s)
	at := strings.IndexByte(lower, '@')
	if at < 0 {
		// No '@'  -- must be a plain duration.
		d, err := time.ParseDuration(s)
		if err != nil {
			return snapshotSched{}, fmt.Errorf("schedule %q: expected a duration, \"daily@HH:MM\", or \"day@HH:MM\"", s)
		}
		return snapshotSched{kind: "interval", d: d}, nil
	}
	prefix, timePart := lower[:at], s[at+1:]
	t, err := time.Parse("15:04", timePart)
	if err != nil {
		return snapshotSched{}, fmt.Errorf("schedule %q: time must be HH:MM", s)
	}
	if prefix == "daily" {
		return snapshotSched{kind: "daily", hour: t.Hour(), minute: t.Minute()}, nil
	}
	wd, err := parseWeekday(prefix)
	if err != nil {
		return snapshotSched{}, fmt.Errorf("schedule %q: unknown day %q (use daily, sunday, monday, ...)", s, prefix)
	}
	return snapshotSched{kind: "weekly", weekday: wd, hour: t.Hour(), minute: t.Minute()}, nil
}

func parseWeekday(s string) (time.Weekday, error) {
	switch s {
	case "sunday", "sun":
		return time.Sunday, nil
	case "monday", "mon":
		return time.Monday, nil
	case "tuesday", "tue":
		return time.Tuesday, nil
	case "wednesday", "wed":
		return time.Wednesday, nil
	case "thursday", "thu":
		return time.Thursday, nil
	case "friday", "fri":
		return time.Friday, nil
	case "saturday", "sat":
		return time.Saturday, nil
	}
	return 0, fmt.Errorf("unknown weekday %q", s)
}

// nextSnapshotAfter returns when the next snapshot should fire after now (UTC).
func nextSnapshotAfter(sched snapshotSched, now time.Time) time.Time {
	now = now.UTC()
	switch sched.kind {
	case "daily":
		next := time.Date(now.Year(), now.Month(), now.Day(), sched.hour, sched.minute, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		return next
	case "weekly":
		daysUntil := (int(sched.weekday) - int(now.Weekday()) + 7) % 7
		next := time.Date(now.Year(), now.Month(), now.Day()+daysUntil, sched.hour, sched.minute, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.AddDate(0, 0, 7)
		}
		return next
	default: // interval
		jitter := time.Duration(rand.Intn(301)) * time.Second
		return now.Add(sched.d + jitter)
	}
}

// startPeriodicSnapshot publishes a snapshot on the configured schedule.
// A no-op if sched is empty (automatic snapshots disabled). Each tick
// acquires oplock (the same distributed operation lock the /api surface
// uses) before publishing, so this scheduler and any concurrent
// snapshot/cleanup/update/rebuild/prime -- whether running on this replica
// or, when Valkey is enabled, another one -- never overlap; a busy lock
// skips this cycle entirely rather than blocking. debounce mirrors the
// API's non-force snapshot path (see Config.Schedule.SnapshotDebounce).
func startPeriodicSnapshot(syncr *syncerpkg.Syncer, sched snapshotSched, oplock *api.OpLock, indexCache *upstream.IndexCache, debounce time.Duration, vclient valkey.Client) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if sched.kind == "" {
			<-stop
			return
		}
		for {
			next := nextSnapshotAfter(sched, time.Now())
			slog.Info("next scheduled snapshot", "at", next.Format(time.RFC3339))
			select {
			case <-time.After(time.Until(next)):
				safego.Run("periodic snapshot", func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
					defer cancel()
					held, err := oplock.Acquire(ctx, api.OperationLockTTL, schedulerLockWait)
					if err != nil {
						slog.Warn("scheduled snapshot: acquire operation lock", "err", err)
						return
					}
					if held == nil {
						slog.Info("scheduled snapshot skipped: an admin operation is already in progress")
						return
					}
					defer held.Release(ctx)

					if debounce > 0 {
						if age, ok, ageErr := syncr.CurrentSnapshotAge(ctx, time.Now()); ageErr != nil {
							slog.Warn("scheduled snapshot: check current age", "err", ageErr)
						} else if ok && age < debounce {
							slog.Info("scheduled snapshot skipped: within debounce window", "age", age)
							return
						}
					}

					slog.Info("publishing scheduled snapshot")
					opStart := time.Now()
					indexCache.Lock()
					snapNow := time.Now()
					snapErr := syncr.Snapshot(ctx, snapNow)
					indexCache.Unlock()
					metrics.OperationDuration.WithLabelValues(api.ResSnapshot).Observe(time.Since(opStart).Seconds())
					if snapErr != nil {
						metrics.OperationFailuresTotal.WithLabelValues(api.ResSnapshot).Inc()
						slog.Warn("scheduled snapshot failed", "err", snapErr)
					} else {
						writeSnapshotName(snapNow.UTC().Format(syncerpkg.SnapshotIDFormat))
						publishSnapshotPublished(ctx, vclient)
					}
				})
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// publishSnapshotPublished tells every other replica that "current/*" just
// changed, so each can purge its own storage file cache's "current/"
// entries (see internal/storage/filecache.Purger and
// valkeycache.ChannelSnapshotPublished's own doc comment for the full
// reasoning) -- this replica already self-invalidated the exact paths it
// just wrote and doesn't need this notice itself. A no-op when vclient is
// nil (Valkey disabled: single replica, nothing else to notify).
// Fire-and-forget: a publish error is logged, not propagated, matching
// every other pub/sub notice in this codebase.
func publishSnapshotPublished(ctx context.Context, vclient valkey.Client) {
	if vclient == nil {
		return
	}
	if err := valkeycache.Publish(ctx, vclient, valkeycache.ChannelSnapshotPublished, ""); err != nil {
		slog.Warn("publish snapshot-published notice", "err", err)
	}
}

// startPeriodicCleanup runs snapshot pruning and pool GC on the configured
// schedule. Each tick acquires oplock first, same reasoning as
// startPeriodicSnapshot -- cleanup doesn't build the index, so unlike
// snapshot it doesn't also need indexCache's build lock.
func startPeriodicCleanup(syncr *syncerpkg.Syncer, sched snapshotSched, cfg *config.Config, oplock *api.OpLock) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if sched.kind == "" {
			<-stop
			return
		}
		for {
			next := nextSnapshotAfter(sched, time.Now())
			slog.Info("next scheduled cleanup", "at", next.Format(time.RFC3339))
			select {
			case <-time.After(time.Until(next)):
				safego.Run("periodic cleanup", func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
					defer cancel()
					held, err := oplock.Acquire(ctx, api.OperationLockTTL, schedulerLockWait)
					if err != nil {
						slog.Warn("scheduled cleanup: acquire operation lock", "err", err)
						return
					}
					if held == nil {
						slog.Info("scheduled cleanup skipped: an admin operation is already in progress")
						return
					}
					defer held.Release(ctx)

					maxAge, ageErr := config.ParseDuration(cfg.Schedule.Age)
					if ageErr != nil {
						slog.Warn("scheduled cleanup: invalid schedule.age", "err", ageErr)
						return
					}
					slog.Info("running scheduled cleanup")
					opStart := time.Now()
					err = syncr.Cleanup(ctx, cfg.Schedule.History, maxAge, time.Now())
					metrics.OperationDuration.WithLabelValues(api.ResCleanup).Observe(time.Since(opStart).Seconds())
					if err != nil {
						metrics.OperationFailuresTotal.WithLabelValues(api.ResCleanup).Inc()
						slog.Warn("scheduled cleanup failed", "err", err)
					}
				})
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// startPeriodicMerge calls index.Refresh approximately every interval, merging
// any changes written by other instances into the in-memory state. Up to 10
// minutes of jitter is added per cycle so concurrent instances don't all LIST
// the backend at the same moment. Unlike startPeriodicFlush, this never writes  --
// dirty entries are left to the flush goroutine, satisfying the invariant that
// we don't write when we have no changes of our own.
func startPeriodicMerge(index metadata.MetadataIndex, interval time.Duration) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			jitter := time.Duration(rand.Intn(601)) * time.Second
			select {
			case <-time.After(interval + jitter):
				safego.Run("periodic metadata merge", func() {
					if err := index.Refresh(context.Background()); err != nil {
						slog.Warn("periodic metadata merge", "err", err)
					}
				})
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// layoutSaveTracker coordinates, across every replica sharing the same
// Valkey deployment, which one of them saves a given layout grouping's
// metadata each schedule.metadata_flush interval -- see claim. Every replica
// runs its own independent, jittered refresh schedule (see
// startIndexRefresher), so without this, every one of them would
// redundantly re-pull and re-write the same layout's metadata each interval.
type layoutSaveTracker struct {
	client valkey.Client
	keys   valkeycache.Keys
}

// claim reports whether this replica should save key's metadata this
// interval, by attempting to acquire a Valkey SET-NX-PX claim key
// (valkeycache.Keys.MetadataFlushClaim) with a TTL of interval. The lock is
// deliberately never renewed or released: letting it expire naturally is
// what marks the layout due for its next save, one interval later,
// regardless of which replica happens to claim it that time. interval <= 0
// means "never due" -- metadata_flush: "0" disables per-layout saving
// entirely.
func (t *layoutSaveTracker) claim(ctx context.Context, key layoutKey, interval time.Duration) bool {
	if t == nil || t.client == nil || interval <= 0 {
		return false
	}
	_, acquired, err := valkeycache.AcquireLock(ctx, t.client, t.keys.MetadataFlushClaim(key.os, key.codename), interval)
	if err != nil {
		slog.Warn("valkey metadata flush claim failed", "os", key.os, "codename", key.codename, "err", err)
		return false
	}
	return acquired
}

// saveLayoutMetadata persists key's own slice of the metadata index -- its
// own (os, codename) package/source entries plus upstream-fetch state for
// the upstreams that feed it -- if index supports it (see metadata.Backuper)
// and this replica successfully claims responsibility for this interval's
// save of key (see layoutSaveTracker.claim; in a multi-replica deployment,
// exactly one replica's claim succeeds per interval, so the others skip this
// entirely rather than redundantly repeating the same pull-and-write).
// Called after refreshLayoutGroup finishes each layout's own refresh cycle,
// so different layouts' independently-jittered schedules (see
// startIndexRefresher) naturally stagger these saves instead of all layouts
// saving at once. Within one layout, components (main, contrib, non-free,
// ...) are saved one at a time, in a serial loop -- deb822store's compress
// step now reuses a pooled scratch buffer rather than allocating fresh per
// call, so this loop no longer needs its own debug.FreeOSMemory() per
// component; refreshLayoutGroup's own call at the end of its cycle already
// covers whatever this whole loop allocated. Backends without this
// capability (deb822store) are untouched here -- see
// startPeriodicMetadataFlush instead.
func saveLayoutMetadata(ctx context.Context, key layoutKey, upstreams []model.UpstreamSource, deps refreshDeps) {
	b, ok := deps.index.(metadata.Backuper)
	if !ok || !deps.tracker.claim(ctx, key, deps.flushInterval) {
		return
	}

	var components []string
	seenComponent := map[string]bool{}
	namesByComponent := map[string][]string{}
	seenName := map[string]map[string]bool{}
	for _, u := range upstreams {
		if !seenComponent[u.Component] {
			seenComponent[u.Component] = true
			components = append(components, u.Component)
		}
		if seenName[u.Component] == nil {
			seenName[u.Component] = map[string]bool{}
		}
		if !seenName[u.Component][u.Name] {
			seenName[u.Component][u.Name] = true
			namesByComponent[u.Component] = append(namesByComponent[u.Component], u.Name)
		}
	}

	allOK := true
	for _, component := range components {
		if ctx.Err() != nil {
			allOK = false
			break
		}
		scope := metadata.BackupScope{OS: key.os, Codename: key.codename, Component: component, Upstreams: namesByComponent[component]}
		if err := b.Backup(ctx, deps.store, scope); err != nil {
			slog.Warn("layout metadata save failed", "os", key.os, "codename", key.codename, "component", component, "err", err)
			allOK = false
			continue
		}
	}
	if !allOK {
		return
	}
	slog.Info("layout metadata saved", "os", key.os, "codename", key.codename, "components", len(components))
}

// startPeriodicMetadataFlush persists a non-Backuper index (deb822store) to
// store every interval, exactly as this project's periodic metadata save
// always has, plus once more when stopped. interval <= 0 disables it
// entirely, including the final save at stop. A Backuper-backed index
// (valkeystore) is saved per layout instead, right after each layout's own
// refresh cycle (see saveLayoutMetadata, wired into startIndexRefresher) --
// that already happens periodically on each layout's own schedule, so this
// function is a no-op for it rather than running a second, redundant
// whole-index save on its own separate clock.
func startPeriodicMetadataFlush(index metadata.MetadataIndex, interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	if _, ok := index.(metadata.Backuper); ok {
		return func() {}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				safego.Run("periodic metadata flush", func() {
					if err := index.Flush(context.Background()); err != nil {
						slog.Warn("periodic metadata flush", "err", err)
					}
				})
			case <-stop:
				safego.Run("final metadata flush", func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					if err := index.Flush(ctx); err != nil {
						slog.Warn("final metadata flush", "err", err)
					}
				})
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

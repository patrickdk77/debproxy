package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metadatafactory"
	"github.com/debproxy/debproxy/internal/rebuild"
	"github.com/debproxy/debproxy/internal/server"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storagefactory"
	syncerpkg "github.com/debproxy/debproxy/internal/syncer"
	"github.com/debproxy/debproxy/internal/upstream"
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
  debproxy rebuild [--config path] [--reset]
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

func openBackends(ctx context.Context, cfg *config.Config) (storage.Storage, metadata.MetadataIndex, error) {
	store, err := storagefactory.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	index, err := metadatafactory.New(ctx, store)
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

func loadKey(cfg *config.Config) (*signing.Key, error) {
	if cfg.Signing.PrivateKey == "" {
		return nil, nil
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
	if err := s.Snapshot(ctx, time.Now()); err != nil {
		slog.Error("snapshot after update", "err", err)
		return 1
	}
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
	if err := s.Snapshot(ctx, time.Now()); err != nil {
		slog.Error("snapshot", "err", err)
		return 1
	}
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
	maxAge, err := parseDuration(cfg.MaxSnapshotAge)
	if err != nil {
		slog.Error("invalid max_snapshot_age", "value", cfg.MaxSnapshotAge, "err", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	s := syncerpkg.New(cfg, store, index, key, upstream.NewHTTPClient(cfg.UserAgent), nil, nil)
	if err := s.Cleanup(ctx, cfg.MaxSnapshots, maxAge, time.Now()); err != nil {
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

// parseDuration extends time.ParseDuration with "d" suffix support (e.g. "30d" = 720h).
func parseDuration(s string) (time.Duration, error) {
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
	if *snapshot {
		if err := s.Snapshot(ctx, time.Now()); err != nil {
			slog.Error("snapshot", "err", err)
			return 1
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		slog.Error("storage ping", "err", err)
		return 1
	}
	if err := index.Ping(ctx); err != nil {
		slog.Error("metadata ping", "err", err)
		return 1
	}

	key, err := loadKey(cfg)
	if err != nil {
		slog.Warn("signing key not loaded", "err", err)
	}
	if key != nil {
		fpPath := path.Join(signing.KeysDir, key.Fingerprint()+".asc")
		_, err := store.StatPublished(ctx, fpPath)
		if err != nil && !os.IsNotExist(err) {
			slog.Error("check signing key", "err", err)
			return 1
		}
		if os.IsNotExist(err) {
			if names, err := key.Publish(ctx, store); err != nil {
				slog.Error("publish signing public key", "err", err)
				return 1
			} else {
				slog.Info("published signing public key", "fingerprint", key.Fingerprint(), "files", names)
			}
		} else {
			slog.Debug("signing key already published", "fingerprint", key.Fingerprint())
		}
	}

	httpClient := upstream.NewHTTPClient(cfg.UserAgent)
	indexCache := upstream.NewIndexCache()

	notifier, err := buildNotifier(cfg)
	if err != nil {
		slog.Error("webhook config", "err", err)
		return 1
	}

	var refreshInterval time.Duration
	if cfg.RefreshInterval != "" && cfg.RefreshInterval != "0" {
		d, err := time.ParseDuration(cfg.RefreshInterval)
		if err != nil {
			slog.Error("invalid refresh_interval", "value", cfg.RefreshInterval, "err", err)
			return 1
		}
		refreshInterval = d
	}

	snapSched, err := parseSnapshotSchedule(cfg.SnapshotSchedule)
	if err != nil {
		slog.Error("invalid snapshot_schedule", "value", cfg.SnapshotSchedule, "err", err)
		return 1
	}
	cleanupSched, err := parseSnapshotSchedule(cfg.CleanupSchedule)
	if err != nil {
		slog.Error("invalid cleanup_schedule", "value", cfg.CleanupSchedule, "err", err)
		return 1
	}

	syncr := syncerpkg.New(cfg, store, index, key, httpClient, indexCache, notifier)
	if err := syncr.PreloadExistsCache(context.Background()); err != nil {
		slog.Warn("preload pool exists cache", "err", err)
	}

	// Flush dirty metadata every 5 minutes. On graceful shutdown the stop func
	// does one final flush. SIGKILL cannot be caught; the 5-minute interval
	// limits how much index data is lost in that case (it can be rebuilt with
	// `debproxy rebuild` if needed).
	stopFlush := startPeriodicFlush(index, 5*time.Minute)
	stopMerge := startPeriodicMerge(index, time.Hour)
	stopRefresher := startIndexRefresher(cfg, httpClient, indexCache, refreshInterval, syncr)
	stopSnapshotter := startPeriodicSnapshot(syncr, snapSched)
	stopCleaner := startPeriodicCleanup(syncr, cleanupSched, cfg)

	if cfg.MetricsAddr != "" {
		metricsSrv := &http.Server{Addr: cfg.MetricsAddr, Handler: promhttp.Handler()}
		go func() {
			slog.Info("metrics listening", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics serve", "err", err)
			}
		}()
	}

	srv := &http.Server{Addr: *addr, Handler: server.New(cfg, store, index, key, httpClient, indexCache, notifier).Handler()}
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

	stopRefresher()
	stopSnapshotter()
	stopCleaner()
	stopMerge()
	stopFlush()
	return 0
}

// startIndexRefresher pre-warms the upstream index cache shortly after startup,
// then re-fetches all upstream indices every interval (if > 0). After each
// refresh it calls syncr.UpdateWithCache to pull any newer auto_update packages.
// Initial delay is 2 minutes plus up to 60 seconds of random jitter.
// Each periodic refresh adds up to 5 minutes of random jitter.
// Returns a stop function that cancels any in-progress refresh and waits for it to finish.
func startIndexRefresher(cfg *config.Config, client *http.Client, cache *upstream.IndexCache, interval time.Duration, syncr *syncerpkg.Syncer) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		initialDelay := 2*time.Minute + time.Duration(rand.Intn(61))*time.Second
		select {
		case <-time.After(initialDelay):
		case <-stop:
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-stop; cancel() }()
		refreshIndexes(ctx, cfg, client, cache, syncr)
		if interval <= 0 {
			return
		}
		for {
			jitter := time.Duration(rand.Intn(301)) * time.Second
			select {
			case <-time.After(interval + jitter):
				refreshIndexes(ctx, cfg, client, cache, syncr)
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

// refreshIndexes sequentially fetches each unique upstream index into the cache,
// then runs the auto-update check against the freshly-fetched data.
// Sources are deduplicated by (URL, suite, component) — the same key the cache uses.
func refreshIndexes(ctx context.Context, cfg *config.Config, client *http.Client, cache *upstream.IndexCache, syncr *syncerpkg.Syncer) {
	seen := map[string]bool{}
	for _, layout := range cfg.ResolvedLayouts {
		for _, src := range layout.Upstreams {
			key := src.URL + "\x00" + src.Suite + "\x00" + src.Component
			if seen[key] {
				continue
			}
			seen[key] = true
			if ctx.Err() != nil {
				return
			}
			slog.Info("refreshing upstream index", "upstream", src.Name, "suite", src.Suite, "component", src.Component)
			f := upstream.NewFetcherWithCache(src, client, cache)
			if _, err := f.FetchIndex(ctx); err != nil {
				slog.Warn("upstream index refresh failed", "upstream", src.Name, "suite", src.Suite, "component", src.Component, "err", err)
			}
		}
	}
	slog.Info("upstream index refresh complete", "sources", len(seen))

	if ctx.Err() != nil {
		return
	}
	if err := syncr.UpdateWithCache(ctx, cache); err != nil {
		slog.Warn("post-refresh update failed", "err", err)
	}
}

// snapshotSched holds a parsed snapshot_schedule value.
type snapshotSched struct {
	kind    string        // "interval", "daily", "weekly"
	d       time.Duration // interval mode
	hour    int           // daily/weekly: UTC hour
	minute  int           // daily/weekly: UTC minute
	weekday time.Weekday  // weekly only
}

// parseSnapshotSchedule parses snapshot_schedule from config. Accepted forms:
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
		// No '@' — must be a plain duration.
		d, err := time.ParseDuration(s)
		if err != nil {
			return snapshotSched{}, fmt.Errorf("snapshot_schedule %q: expected a duration, \"daily@HH:MM\", or \"day@HH:MM\"", s)
		}
		return snapshotSched{kind: "interval", d: d}, nil
	}
	prefix, timePart := lower[:at], s[at+1:]
	t, err := time.Parse("15:04", timePart)
	if err != nil {
		return snapshotSched{}, fmt.Errorf("snapshot_schedule %q: time must be HH:MM", s)
	}
	if prefix == "daily" {
		return snapshotSched{kind: "daily", hour: t.Hour(), minute: t.Minute()}, nil
	}
	wd, err := parseWeekday(prefix)
	if err != nil {
		return snapshotSched{}, fmt.Errorf("snapshot_schedule %q: unknown day %q (use daily, sunday, monday, ...)", s, prefix)
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
// A no-op if sched is empty (automatic snapshots disabled).
func startPeriodicSnapshot(syncr *syncerpkg.Syncer, sched snapshotSched) func() {
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
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
				slog.Info("publishing scheduled snapshot")
				if err := syncr.Snapshot(ctx, time.Now()); err != nil {
					slog.Warn("scheduled snapshot failed", "err", err)
				}
				cancel()
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

// startPeriodicCleanup runs snapshot pruning and pool GC on the configured schedule.
func startPeriodicCleanup(syncr *syncerpkg.Syncer, sched snapshotSched, cfg *config.Config) func() {
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
				maxAge, err := parseDuration(cfg.MaxSnapshotAge)
				if err != nil {
					slog.Warn("scheduled cleanup: invalid max_snapshot_age", "err", err)
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				slog.Info("running scheduled cleanup")
				if err := syncr.Cleanup(ctx, cfg.MaxSnapshots, maxAge, time.Now()); err != nil {
					slog.Warn("scheduled cleanup failed", "err", err)
				}
				cancel()
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
// the backend at the same moment. Unlike startPeriodicFlush, this never writes —
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
				if err := index.Refresh(context.Background()); err != nil {
					slog.Warn("periodic metadata merge", "err", err)
				}
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

// startPeriodicFlush calls index.Flush every interval. The returned stop
// function triggers one final flush and blocks until it completes.
func startPeriodicFlush(index metadata.MetadataIndex, interval time.Duration) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := index.Flush(context.Background()); err != nil {
					slog.Warn("metadata flush", "err", err)
				}
			case <-stop:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := index.Flush(ctx); err != nil {
					slog.Warn("metadata final flush", "err", err)
				}
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

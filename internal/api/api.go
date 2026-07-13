// Package api implements debproxy's authenticated, permission-gated /api/v1
// HTTP surface: triggering (or querying) the admin actions -- snapshot,
// cleanup, update, rebuild, prime, publish-key -- that were previously only
// reachable via CLI subcommand or background scheduler.
package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/auth"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/signing"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/syncer"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
	"github.com/debproxy/debproxy/internal/webhook"
)

// Resource/action taxonomy -- the only values api: config keys may name (see
// validatePermissions) and the labels used for cfg.API lookups and metrics.
const (
	ResSnapshot   = "snapshot"
	ResCleanup    = "cleanup"
	ResUpdate     = "update"
	ResRebuild    = "rebuild"
	ResPrime      = "prime"
	ResPublishKey = "publish-key"
	ResJobs       = "jobs"

	ActCreate  = "create"
	ActCurrent = "current"
	ActRun     = "run"
	ActRead    = "read"
)

var knownActions = map[string]map[string]bool{
	ResSnapshot:   {ActCreate: true, ActCurrent: true},
	ResCleanup:    {ActRun: true},
	ResUpdate:     {ActRun: true},
	ResRebuild:    {ActRun: true},
	ResPrime:      {ActRun: true},
	ResPublishKey: {ActRun: true},
	ResJobs:       {ActRead: true},
}

// defaultJobQueueMax is used when Config.APIJobQueueMax is unset (<= 0),
// sized for bulk prime submissions (hundreds of packages at once), not a
// small cap.
const defaultJobQueueMax = 1000

// snapshotLockWait bounds how long the synchronous POST /api/v1/snapshot
// handler waits for the operation lock before giving up with 503 --
// deliberately short: it's the CI/CD hot path, and blocking behind a
// possibly-hours-long async op is the wrong tradeoff (see the design doc).
const snapshotLockWait = 5 * time.Second

// API is debproxy's /api/v1 HTTP surface.
type API struct {
	cfg          *config.Config
	authn        *auth.Authenticator
	syncr        *syncer.Syncer
	store        storage.Storage
	index        metadata.MetadataIndex
	indexCache   *upstream.IndexCache
	httpClient   *http.Client
	key          *signing.Key
	oplock       *OpLock
	queue        *operationRunner
	debounce     time.Duration
	snapshotWait time.Duration
	vclient      valkey.Client // nil unless Valkey is enabled; see handleSnapshotCreate
}

// Deps bundles New's dependencies.
type Deps struct {
	Config           *config.Config
	Store            storage.Storage
	Index            metadata.MetadataIndex
	Syncer           *syncer.Syncer
	IndexCache       *upstream.IndexCache
	HTTPClient       *http.Client
	Key              *signing.Key
	OpLock           *OpLock
	VClient          valkey.Client
	VKeys            valkeycache.Keys
	Notifier         *webhook.Notifier
	SnapshotDebounce time.Duration
}

// New constructs an API, validating auth config and the api: permission map
// up front (fail loud at startup on a config mistake, matching how
// auth.New validates Basic/OIDC config) and starting the async job queue's
// worker. Call Close on shutdown.
func New(deps Deps) (*API, error) {
	authn, err := auth.New(deps.Config.Auth, deps.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("auth config: %w", err)
	}
	if err := validatePermissions(deps.Config.API); err != nil {
		return nil, err
	}

	queueMax := deps.Config.APIJobQueueMax
	if queueMax <= 0 {
		queueMax = defaultJobQueueMax
	}

	a := &API{
		cfg:          deps.Config,
		authn:        authn,
		syncr:        deps.Syncer,
		store:        deps.Store,
		index:        deps.Index,
		indexCache:   deps.IndexCache,
		httpClient:   deps.HTTPClient,
		key:          deps.Key,
		oplock:       deps.OpLock,
		debounce:     deps.SnapshotDebounce,
		snapshotWait: snapshotLockWait,
		vclient:      deps.VClient,
	}
	a.queue = newOperationRunner(queueMax, deps.OpLock, deps.IndexCache, deps.VClient, deps.VKeys, deps.Notifier)
	a.queue.start()
	return a, nil
}

// Close stops the async job queue's worker.
func (a *API) Close() { a.queue.stop() }

// validatePermissions rejects any api: config entry naming a resource or
// action outside the fixed taxonomy above -- a typo'd resource/action name
// would otherwise silently grant no one access (an unconfigured
// resource/action 404s, per the design's instant-404 model) rather than
// failing loudly at startup.
func validatePermissions(apiCfg map[string]map[string][]string) error {
	for resource, actions := range apiCfg {
		known, ok := knownActions[resource]
		if !ok {
			return fmt.Errorf("api config: unknown resource %q", resource)
		}
		for action := range actions {
			if !known[action] {
				return fmt.Errorf("api config: unknown action %q for resource %q", action, resource)
			}
		}
	}
	return nil
}

// Handler returns the /api/v1 HTTP handler, ready to be mounted at "/api/"
// on the main listener's mux.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/snapshot", a.guard(ResSnapshot, ActCreate, a.handleSnapshotCreate))
	mux.HandleFunc("GET /api/v1/snapshot/current", a.guard(ResSnapshot, ActCurrent, a.handleSnapshotCurrent))
	mux.HandleFunc("POST /api/v1/cleanup", a.guard(ResCleanup, ActRun, a.handleCleanup))
	mux.HandleFunc("POST /api/v1/update", a.guard(ResUpdate, ActRun, a.handleUpdate))
	mux.HandleFunc("POST /api/v1/rebuild", a.guard(ResRebuild, ActRun, a.handleRebuild))
	mux.HandleFunc("POST /api/v1/prime", a.guard(ResPrime, ActRun, a.handlePrime))
	mux.HandleFunc("POST /api/v1/publish-key", a.guard(ResPublishKey, ActRun, a.handlePublishKey))
	mux.HandleFunc("GET /api/v1/jobs/{id}", a.guard(ResJobs, ActRead, a.handleJobStatus))
	return mux
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/debproxy/debproxy/internal/auth"
	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/rebuild"
	"github.com/debproxy/debproxy/internal/syncer"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("api: encode response failed", "err", err)
	}
}

// decodeBody decodes r's JSON body into v, if any. An empty body is not an
// error -- every /api/v1 request body is optional, defaulting every field to
// its zero value (false/""/nil), which is always the safe/conservative
// choice per the design doc (e.g. force defaults to false).
func decodeBody(r *http.Request, v any) error {
	if r.ContentLength == 0 {
		return nil
	}
	return json.NewDecoder(r.Body).Decode(v)
}

// --- snapshot ---

type snapshotRequest struct {
	Force bool `json:"force"`
}

func (a *API) handleSnapshotCreate(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	var req snapshotRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	held, err := a.oplock.Acquire(ctx, OperationLockTTL, a.snapshotWait)
	if err != nil {
		slog.Error("api snapshot: acquire operation lock", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if held == nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "an admin operation is already in progress", http.StatusServiceUnavailable)
		return
	}
	defer held.Release(ctx)

	if !req.Force && a.debounce > 0 {
		if age, ok, ageErr := a.syncr.CurrentSnapshotAge(ctx, time.Now()); ageErr != nil {
			slog.Warn("api snapshot: check current age", "err", ageErr)
		} else if ok && age < a.debounce {
			name, nameErr := a.syncr.CurrentSnapshotName(ctx)
			if nameErr != nil {
				slog.Error("api snapshot: read debounced current name", "err", nameErr)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"snapshot": name})
			return
		}
	}

	opStart := time.Now()
	a.indexCache.Lock()
	snapNow := time.Now()
	err = a.syncr.Snapshot(ctx, snapNow)
	a.indexCache.Unlock()
	metrics.OperationDuration.WithLabelValues(ResSnapshot).Observe(time.Since(opStart).Seconds())
	if err != nil {
		metrics.OperationFailuresTotal.WithLabelValues(ResSnapshot).Inc()
		slog.Error("api snapshot", "err", err)
		http.Error(w, "snapshot failed", http.StatusInternalServerError)
		return
	}
	a.publishSnapshotPublished(ctx)
	writeJSON(w, http.StatusOK, map[string]string{"snapshot": snapNow.UTC().Format(syncer.SnapshotIDFormat)})
}

// publishSnapshotPublished tells every other replica that "current/*" just
// changed, so each can purge its own storage file cache's "current/"
// entries (see internal/storage/filecache.Purger) -- this replica already
// self-invalidated the exact paths it just wrote (see filecache.Store's
// WriteFile override) and doesn't need this notice itself. A no-op when
// Valkey is disabled (single replica: nothing else to notify) or the file
// cache is disabled (Store.WriteFile self-invalidation is the only purge
// mechanism that ever mattered locally either way). Fire-and-forget, same
// as every other pub/sub notice in this codebase: a publish error is
// logged, not propagated, since it would only ever delay -- never
// permanently corrupt -- another replica's cache.
func (a *API) publishSnapshotPublished(ctx context.Context) {
	if a.vclient == nil {
		return
	}
	if err := valkeycache.Publish(ctx, a.vclient, valkeycache.ChannelSnapshotPublished, ""); err != nil {
		slog.Warn("publish snapshot-published notice", "err", err)
	}
}

func (a *API) handleSnapshotCurrent(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	name, err := a.syncr.CurrentSnapshotName(r.Context())
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		slog.Error("api snapshot current", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"snapshot": name})
}

// --- cleanup / update (async, no request body) ---

func (a *API) handleCleanup(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	a.enqueueAndRespond(w, r, JobCleanup, func(ctx context.Context) error {
		maxAge, err := config.ParseDuration(a.cfg.Schedule.Age)
		if err != nil {
			return err
		}
		if err := a.syncr.Cleanup(ctx, a.cfg.Schedule.History, maxAge, time.Now()); err != nil {
			return err
		}
		return a.index.Flush(ctx)
	})
}

func (a *API) handleUpdate(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	a.enqueueAndRespond(w, r, JobUpdate, func(ctx context.Context) error {
		// Syncer.Update takes a.indexCache's build lock internally -- the
		// worker must NOT also wrap this call in it (see indexLockedKinds).
		if err := a.syncr.Update(ctx); err != nil {
			return err
		}
		return a.index.Flush(ctx)
	})
}

// --- rebuild ---

type rebuildRequest struct {
	// Reset defaults to false over HTTP (opt-in true via body), unlike the
	// CLI's --reset which defaults true: reset:true briefly empties the live
	// in-memory index that /live and pool requests read, which is fine for
	// the CLI's throwaway offline process but not a safe default for a
	// request against a live server.
	Reset bool `json:"reset"`
}

func (a *API) handleRebuild(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	var req rebuildRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	a.enqueueAndRespond(w, r, JobRebuild, func(ctx context.Context) error {
		if err := rebuild.Run(ctx, a.cfg, a.store, a.index, rebuild.Options{ResetIndex: req.Reset, HTTPClient: a.httpClient}); err != nil {
			return err
		}
		return a.index.Flush(ctx)
	})
}

// --- prime ---

type primeRequest struct {
	OS        string   `json:"os"`
	Codename  string   `json:"codename"`
	Component string   `json:"component"`
	Packages  []string `json:"packages"`
}

func (a *API) handlePrime(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	var req primeRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.OS == "" || req.Codename == "" || len(req.Packages) == 0 {
		http.Error(w, "os, codename, and packages are required", http.StatusBadRequest)
		return
	}
	component := req.Component
	if component == "" {
		component = "main"
	}
	a.enqueueAndRespond(w, r, JobPrime, func(ctx context.Context) error {
		if err := a.syncr.Prime(ctx, req.OS, req.Codename, component, req.Packages); err != nil {
			return err
		}
		return a.index.Flush(ctx)
	})
}

// --- publish-key (sync, no operation lock -- writes only key files) ---

func (a *API) handlePublishKey(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	names, err := a.key.Publish(r.Context(), a.store)
	if err != nil {
		slog.Error("api publish-key", "err", err)
		http.Error(w, "publish failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"files": names})
}

// --- jobs ---

func (a *API) handleJobStatus(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	id := r.PathValue("id")
	job, ok, err := a.queue.status(r.Context(), id)
	if err != nil {
		slog.Error("api job status", "job_id", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// --- shared async enqueue/response helper ---

func (a *API) enqueueAndRespond(w http.ResponseWriter, r *http.Request, kind JobKind, run func(ctx context.Context) error) {
	id, err := a.queue.enqueue(kind, run)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{
			"job_id":    id,
			"operation": string(kind),
			"status":    string(StatusQueued),
		})
	case errors.Is(err, errDuplicateKind):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "operation in progress", "job_id": id})
	case errors.Is(err, errQueueFull):
		http.Error(w, "job queue is full", http.StatusServiceUnavailable)
	case errors.Is(err, errShuttingDown):
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
	default:
		slog.Error("api: enqueue job", "kind", kind, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/safego"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
	"github.com/debproxy/debproxy/internal/webhook"
)

// JobKind identifies which async admin operation a Job runs.
type JobKind string

const (
	JobCleanup JobKind = "cleanup"
	JobUpdate  JobKind = "update"
	JobRebuild JobKind = "rebuild"
	JobPrime   JobKind = "prime"
)

// JobStatus is a Job's lifecycle state.
type JobStatus string

const (
	StatusQueued    JobStatus = "queued"
	StatusRunning   JobStatus = "running"
	StatusSucceeded JobStatus = "succeeded"
	StatusFailed    JobStatus = "failed"
)

// Job is the status record for one async admin operation. Holds only coarse
// metadata (kind, status, timestamps, error) -- never secrets or tokens --
// since it's readable via GET /api/v1/jobs/{id} by anyone with jobs.read.
type Job struct {
	ID         string     `json:"job_id"`
	Kind       JobKind    `json:"operation"`
	Status     JobStatus  `json:"status"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

var (
	errDuplicateKind = errors.New("operation already in progress")
	errQueueFull     = errors.New("job queue is full")
	errShuttingDown  = errors.New("job queue is shutting down")
)

// indexLockedKinds are job kinds whose underlying operation does not already
// take upstream.IndexCache's own build lock (unlike JobUpdate, which runs
// Syncer.Update -- fixed to take that lock internally, see syncer.go) and so
// must be wrapped in it here by the worker, nested inside the operation
// lock, before running. JobCleanup doesn't build the index at all, so it
// isn't listed either.
var indexLockedKinds = map[JobKind]bool{
	JobRebuild: true,
	JobPrime:   true,
}

type queuedJob struct {
	job Job
	run func(ctx context.Context) error
}

// operationRunner is a single-worker FIFO queue plus job status registry for
// the four async admin operations. See the design doc's "Concurrency /
// locking model" section for the full contract: prime always enqueues
// (never dedups -- a bulk submission of hundreds must all eventually run);
// update/cleanup/rebuild enqueue unless a job of the same kind is already
// queued or running on this replica, in which case enqueue returns that
// job's ID via errDuplicateKind. The queue is bounded by max; enqueue
// returns errQueueFull past that.
type operationRunner struct {
	max        int
	oplock     *OpLock
	indexCache *upstream.IndexCache
	store      jobStore
	notifier   *webhook.Notifier

	mu      sync.Mutex
	queue   []queuedJob
	active  map[JobKind]string // kind -> job ID currently queued or running (per-replica dedup)
	notify  chan struct{}
	stopped bool // set by stop, under mu -- see dequeue/enqueue

	runCtx    context.Context // passed to every job's run func; canceled by stop
	runCancel context.CancelFunc
	stopCh    chan struct{}
	doneCh    chan struct{}
}

func newOperationRunner(max int, oplock *OpLock, indexCache *upstream.IndexCache, vclient valkey.Client, vkeys valkeycache.Keys, notifier *webhook.Notifier) *operationRunner {
	runCtx, runCancel := context.WithCancel(context.Background())
	return &operationRunner{
		max:        max,
		oplock:     oplock,
		indexCache: indexCache,
		store:      newJobStore(vclient, vkeys),
		notifier:   notifier,
		active:     map[JobKind]string{},
		notify:     make(chan struct{}, 1),
		runCtx:     runCtx,
		runCancel:  runCancel,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// enqueue adds a job of kind to the FIFO queue, running run when it's this
// job's turn.
func (q *operationRunner) enqueue(kind JobKind, run func(ctx context.Context) error) (string, error) {
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return "", errShuttingDown
	}
	if kind != JobPrime {
		if existing, ok := q.active[kind]; ok {
			q.mu.Unlock()
			return existing, errDuplicateKind
		}
	}
	if len(q.queue) >= q.max {
		q.mu.Unlock()
		return "", errQueueFull
	}
	id, err := newJobID()
	if err != nil {
		q.mu.Unlock()
		return "", err
	}
	job := Job{ID: id, Kind: kind, Status: StatusQueued}
	q.queue = append(q.queue, queuedJob{job: job, run: run})
	if kind != JobPrime {
		q.active[kind] = id
	}
	depth := len(q.queue)
	q.mu.Unlock()

	metrics.APIJobQueueDepth.Set(float64(depth))
	if err := q.store.save(context.Background(), job); err != nil {
		slog.Warn("save queued job status", "job_id", id, "err", err)
	}
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return id, nil
}

func (q *operationRunner) status(ctx context.Context, id string) (Job, bool, error) {
	return q.store.get(ctx, id)
}

// start launches the single worker goroutine. Call once.
func (q *operationRunner) start() {
	safego.Go("api job queue worker", q.run)
}

// stop stops intake (further enqueue calls get errShuttingDown), cancels the
// context passed to any in-flight job's run func, abandons whatever is still
// queued behind it (dequeue stops returning items the instant stopped is
// set, under the same lock -- so nothing already in q.queue when stop is
// called ever starts), and waits for the worker to exit. Abandoned jobs'
// effects are durable in storage and they're re-triggerable, matching the
// design doc's shutdown contract.
func (q *operationRunner) stop() {
	q.mu.Lock()
	q.stopped = true
	q.mu.Unlock()
	close(q.stopCh)
	q.runCancel()
	<-q.doneCh
}

func (q *operationRunner) dequeue() (queuedJob, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped || len(q.queue) == 0 {
		return queuedJob{}, false
	}
	next := q.queue[0]
	q.queue = q.queue[1:]
	metrics.APIJobQueueDepth.Set(float64(len(q.queue)))
	return next, true
}

func (q *operationRunner) clearActive(kind JobKind, id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active[kind] == id {
		delete(q.active, kind)
	}
}

func (q *operationRunner) run() {
	defer close(q.doneCh)
	for {
		qj, ok := q.dequeue()
		if !ok {
			select {
			case <-q.notify:
				continue
			case <-q.stopCh:
				return
			}
		}
		safego.Run("api job "+string(qj.job.Kind), func() { q.runOne(qj) })
	}
}

func (q *operationRunner) runOne(qj queuedJob) {
	// Status saves use a fresh background context, deliberately not runCtx:
	// they must still complete during shutdown (so the job's final status is
	// durably recorded) even though runCtx -- passed to the operation itself
	// -- may already be canceled by then.
	saveCtx := context.Background()
	job := qj.job
	job.Status = StatusRunning
	now := time.Now()
	job.StartedAt = &now
	if err := q.store.save(saveCtx, job); err != nil {
		slog.Warn("save running job status", "job_id", job.ID, "err", err)
	}

	start := time.Now()
	held, err := q.oplock.Acquire(q.runCtx, OperationLockTTL, 0)
	if err == nil {
		if held == nil {
			err = errors.New("operation lock unavailable")
		} else {
			if indexLockedKinds[job.Kind] {
				q.indexCache.Lock()
			}
			_, stopRenew := held.StartRenewing(q.runCtx, OperationLockTTL, OperationLockRenewInterval)
			err = qj.run(q.runCtx)
			stopRenew()
			if indexLockedKinds[job.Kind] {
				q.indexCache.Unlock()
			}
			if rerr := held.Release(saveCtx); rerr != nil {
				slog.Warn("release operation lock", "job_id", job.ID, "err", rerr)
			}
		}
	}
	metrics.OperationDuration.WithLabelValues(string(job.Kind)).Observe(time.Since(start).Seconds())

	finished := time.Now()
	job.FinishedAt = &finished
	if err != nil {
		job.Status = StatusFailed
		job.Error = err.Error()
		metrics.OperationFailuresTotal.WithLabelValues(string(job.Kind)).Inc()
		slog.Error("async operation failed", "job_id", job.ID, "kind", job.Kind, "err", err)
	} else {
		job.Status = StatusSucceeded
		slog.Info("async operation succeeded", "job_id", job.ID, "kind", job.Kind)
	}
	if serr := q.store.save(saveCtx, job); serr != nil {
		slog.Warn("save finished job status", "job_id", job.ID, "err", serr)
	}
	q.clearActive(job.Kind, job.ID)
	q.fireWebhook(job)
}

func (q *operationRunner) fireWebhook(job Job) {
	if q.notifier == nil {
		return
	}
	q.notifier.Fire(webhook.Event{
		Kind:      webhook.EventKindJob,
		JobID:     job.ID,
		Operation: string(job.Kind),
		Status:    string(job.Status),
		Error:     job.Error,
	})
}

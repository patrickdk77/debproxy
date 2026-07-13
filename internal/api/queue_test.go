package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

func newTestRunner(t *testing.T, max int) *operationRunner {
	t.Helper()
	oplock := NewOpLock(nil, valkeycache.Keys{})
	r := newOperationRunner(max, oplock, upstream.NewIndexCache(), nil, valkeycache.Keys{}, nil)
	r.start()
	t.Cleanup(r.stop)
	return r
}

func waitForStatus(t *testing.T, r *operationRunner, id string, want JobStatus, timeout time.Duration) Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		job, ok, err := r.status(context.Background(), id)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if ok && job.Status == want {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for job %s to reach status %s (last: %+v, ok=%v)", id, want, job, ok)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOperationRunner_RunsAndSucceeds(t *testing.T) {
	r := newTestRunner(t, 10)
	id, err := r.enqueue(JobUpdate, func(ctx context.Context) error { return nil })
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	job := waitForStatus(t, r, id, StatusSucceeded, 2*time.Second)
	if job.Kind != JobUpdate {
		t.Fatalf("got kind %q", job.Kind)
	}
	if job.StartedAt == nil || job.FinishedAt == nil {
		t.Fatal("expected StartedAt/FinishedAt to be set")
	}
}

func TestOperationRunner_RunFailureRecorded(t *testing.T) {
	r := newTestRunner(t, 10)
	id, err := r.enqueue(JobCleanup, func(ctx context.Context) error { return errors.New("boom") })
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	job := waitForStatus(t, r, id, StatusFailed, 2*time.Second)
	if job.Error != "boom" {
		t.Fatalf("got error %q", job.Error)
	}
}

func TestOperationRunner_SameKindDedup(t *testing.T) {
	r := newTestRunner(t, 10)
	block := make(chan struct{})
	id1, err := r.enqueue(JobUpdate, func(ctx context.Context) error { <-block; return nil })
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Give the worker a moment to pick it up; it's "active" (queued or
	// running) either way, so the exact timing doesn't matter for dedup.
	time.Sleep(50 * time.Millisecond)

	id2, err := r.enqueue(JobUpdate, func(ctx context.Context) error { return nil })
	if !errors.Is(err, errDuplicateKind) {
		t.Fatalf("expected errDuplicateKind, got err=%v id=%v", err, id2)
	}
	if id2 != id1 {
		t.Fatalf("expected the duplicate error to report the original job id %q, got %q", id1, id2)
	}
	close(block)
	waitForStatus(t, r, id1, StatusSucceeded, 2*time.Second)
}

func TestOperationRunner_DifferentKindDoesNotDedup(t *testing.T) {
	r := newTestRunner(t, 10)
	block := make(chan struct{})
	defer close(block)
	if _, err := r.enqueue(JobUpdate, func(ctx context.Context) error { <-block; return nil }); err != nil {
		t.Fatalf("enqueue update: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if _, err := r.enqueue(JobCleanup, func(ctx context.Context) error { return nil }); err != nil {
		t.Fatalf("expected a different kind to enqueue independently, got %v", err)
	}
}

func TestOperationRunner_PrimeNeverDedups(t *testing.T) {
	r := newTestRunner(t, 10)
	block := make(chan struct{})
	id1, err := r.enqueue(JobPrime, func(ctx context.Context) error { <-block; return nil })
	if err != nil {
		t.Fatalf("enqueue 1: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	id2, err := r.enqueue(JobPrime, func(ctx context.Context) error { return nil })
	if err != nil {
		t.Fatalf("expected prime to always enqueue, got err=%v", err)
	}
	if id2 == id1 {
		t.Fatal("expected a distinct job id for the second prime")
	}
	close(block)
	waitForStatus(t, r, id1, StatusSucceeded, 2*time.Second)
	waitForStatus(t, r, id2, StatusSucceeded, 2*time.Second)
}

func TestOperationRunner_QueueFull(t *testing.T) {
	r := newTestRunner(t, 1)
	block := make(chan struct{})
	defer close(block)

	// prime never dedups, so two enqueues reliably occupy (1) the running
	// slot and (2) the one queue slot, regardless of exactly when the
	// worker picks up the first one.
	if _, err := r.enqueue(JobPrime, func(ctx context.Context) error { <-block; return nil }); err != nil {
		t.Fatalf("enqueue 1: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let the worker dequeue job 1
	if _, err := r.enqueue(JobPrime, func(ctx context.Context) error { <-block; return nil }); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}
	if _, err := r.enqueue(JobPrime, func(ctx context.Context) error { return nil }); !errors.Is(err, errQueueFull) {
		t.Fatalf("expected errQueueFull, got %v", err)
	}
}

func TestOperationRunner_StopAbandonsQueueAndCancelsInFlight(t *testing.T) {
	oplock := NewOpLock(nil, valkeycache.Keys{})
	r := newOperationRunner(10, oplock, upstream.NewIndexCache(), nil, valkeycache.Keys{}, nil)
	r.start()

	inFlightCtxErr := make(chan error, 1)
	started := make(chan struct{})
	id1, err := r.enqueue(JobUpdate, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		inFlightCtxErr <- ctx.Err()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("enqueue in-flight job: %v", err)
	}
	<-started // make sure it's actually running before enqueuing the queued one

	id2, err := r.enqueue(JobCleanup, func(ctx context.Context) error {
		t.Error("queued job should have been abandoned by stop, never run")
		return nil
	})
	if err != nil {
		t.Fatalf("enqueue queued job: %v", err)
	}

	r.stop()

	select {
	case err := <-inFlightCtxErr:
		if err == nil {
			t.Fatal("expected the in-flight job's context to be canceled by stop")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the in-flight job to observe cancellation")
	}

	job1, ok, err := r.status(context.Background(), id1)
	if err != nil || !ok {
		t.Fatalf("status(id1): ok=%v err=%v", ok, err)
	}
	if job1.Status != StatusFailed {
		t.Fatalf("expected the canceled in-flight job to end up failed, got %q", job1.Status)
	}

	// The queued job never got a chance to update its own status past
	// "queued" (it never ran), so this only confirms it wasn't silently
	// promoted to running/succeeded after stop.
	job2, ok, err := r.status(context.Background(), id2)
	if err != nil || !ok {
		t.Fatalf("status(id2): ok=%v err=%v", ok, err)
	}
	if job2.Status != StatusQueued {
		t.Fatalf("expected the abandoned queued job to remain queued, got %q", job2.Status)
	}

	if _, err := r.enqueue(JobRebuild, func(ctx context.Context) error { return nil }); !errors.Is(err, errShuttingDown) {
		t.Fatalf("expected enqueue after stop to return errShuttingDown, got %v", err)
	}
}

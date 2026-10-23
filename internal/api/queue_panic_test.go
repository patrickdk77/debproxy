package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestRunOnePanicReleasesEverything is the regression test for a recovered
// panic leaving the process wedged. Before the defers, a panic inside a
// rebuild left the index build lock held, the operation lock renewed
// until shutdown, and the job kind answering "already active" until
// restart. All three must be released, and the job must land as failed
// with the panic in its error.
func TestRunOnePanicReleasesEverything(t *testing.T) {
	r := newTestRunner(t, 10)

	id, err := r.enqueue(JobRebuild, func(ctx context.Context) error {
		panic("simulated rebuild panic")
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	job := waitForStatus(t, r, id, StatusFailed, 5*time.Second)
	if !strings.Contains(job.Error, "panicked") || !strings.Contains(job.Error, "simulated rebuild panic") {
		t.Errorf("job error %q does not record the panic", job.Error)
	}

	// 1. Index build lock released: JobRebuild is an index-locked kind.
	if !r.indexCache.TryLock() {
		t.Fatal("index build lock still held after the panic")
	}
	r.indexCache.Unlock()

	// 2. Active-kind slot cleared: a second rebuild must enqueue, not
	// collide with a ghost of the first.
	id2, err := r.enqueue(JobRebuild, func(ctx context.Context) error { return nil })
	if errors.Is(err, errDuplicateKind) {
		t.Fatal("job kind still marked active after the panic")
	}
	if err != nil {
		t.Fatalf("second enqueue: %v", err)
	}
	waitForStatus(t, r, id2, StatusSucceeded, 5*time.Second)

	// 3. Operation lock released: the local fallback OpLock must be
	// acquirable again. If the renewal goroutine or the held lock
	// survived the panic, Acquire would report it busy.
	held, err := r.oplock.Acquire(context.Background(), OperationLockTTL, 0)
	if err != nil {
		t.Fatalf("Acquire after panic: %v", err)
	}
	if held == nil {
		t.Fatal("operation lock still held after the panic")
	}
	_ = held.Release(context.Background())
}

// TestRunOneNormalFailureStillRecordedAfterRefactor pins that the
// closure refactor did not change the ordinary error path.
func TestRunOneNormalFailureStillRecordedAfterRefactor(t *testing.T) {
	r := newTestRunner(t, 10)
	id, err := r.enqueue(JobRebuild, func(ctx context.Context) error {
		return errors.New("plain failure")
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	job := waitForStatus(t, r, id, StatusFailed, 5*time.Second)
	if job.Error != "plain failure" {
		t.Errorf("error %q, want %q", job.Error, "plain failure")
	}
	if strings.Contains(job.Error, "panicked") {
		t.Errorf("ordinary error mislabeled as a panic: %q", job.Error)
	}
	if !r.indexCache.TryLock() {
		t.Fatal("index build lock held after a normal failure")
	}
	r.indexCache.Unlock()
}

// TestRunOneSuccessReleasesIndexLock covers the happy path for the same
// invariant, so a regression in the defer ordering shows up here even
// when nothing fails.
func TestRunOneSuccessReleasesIndexLock(t *testing.T) {
	r := newTestRunner(t, 10)
	id, err := r.enqueue(JobRebuild, func(ctx context.Context) error { return nil })
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	waitForStatus(t, r, id, StatusSucceeded, 5*time.Second)
	if !r.indexCache.TryLock() {
		t.Fatal("index build lock held after success")
	}
	r.indexCache.Unlock()
}

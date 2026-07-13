package api

import (
	"context"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/valkeycache"
)

// jobTTL bounds how long a finished job's status remains queryable via
// GET /api/v1/jobs/{id} -- an operator visibility/audit window, not a
// tunable correctness parameter.
const jobTTL = 24 * time.Hour

// jobStore persists Job status so a poller can read it. Valkey-backed when
// Valkey is enabled (so any replica behind a load balancer can read a job
// that ran on a different one), or an in-process map otherwise
// (single-replica only -- same split as OpLock's no-Valkey fallback).
type jobStore interface {
	save(ctx context.Context, job Job) error
	get(ctx context.Context, id string) (Job, bool, error)
}

func newJobStore(vclient valkey.Client, keys valkeycache.Keys) jobStore {
	if vclient != nil {
		return &valkeyJobStore{v: vclient, keys: keys}
	}
	return &localJobStore{jobs: map[string]Job{}}
}

type localJobStore struct {
	mu   sync.Mutex
	jobs map[string]Job
}

func (s *localJobStore) save(_ context.Context, job Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = job
	return nil
}

func (s *localJobStore) get(_ context.Context, id string) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	return job, ok, nil
}

type valkeyJobStore struct {
	v    valkey.Client
	keys valkeycache.Keys
}

func (s *valkeyJobStore) save(ctx context.Context, job Job) error {
	return valkeycache.SetJSONEx(ctx, s.v, s.keys.Job(job.ID), job, jobTTL)
}

func (s *valkeyJobStore) get(ctx context.Context, id string) (Job, bool, error) {
	job, ok, err := valkeycache.GetJSON[Job](ctx, s.v, s.keys.Job(id))
	if err != nil || !ok {
		return Job{}, ok, err
	}
	return *job, true, nil
}

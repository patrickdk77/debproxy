package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata/valkeystore"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/testsupport"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// testValkeyAddr is set by TestMain once the shared container is up.
var testValkeyAddr string

func TestMain(m *testing.M) {
	testsupport.RunMain(m, &testValkeyAddr)
}

// TestReconcileIndexIfEmptySkipsWhenAnotherReplicaHoldsTheLock is the
// regression test for the actual production incident: two replicas
// restarting seconds apart both saw an empty index and both independently
// ran the full restore-then-pool-walk, each taking 60-90s. With the
// OperationLock held by another "replica" (simulated here by acquiring it
// directly), this replica must skip reconciliation entirely rather than
// redundantly repeating it.
func TestReconcileIndexIfEmptySkipsWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	ctx := context.Background()
	client := testsupport.NewTestClient(t, testValkeyAddr)
	vkeys := valkeycache.Keys{Prefix: "reconcile-lock-test:"}

	index := valkeystore.New(client, vkeys.Prefix)
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// A pool file that would be picked up if reconciliation actually ran --
	// used to prove it did NOT run.
	debData := buildTestDeb(t, "shouldnotbeindexed", "1.0")
	if err := store.PutFile(ctx, "pool/ubuntu/noble/some-upstream/main/s/shouldnotbeindexed/shouldnotbeindexed_1.0_amd64.deb", bytes.NewReader(debData), int64(len(debData))); err != nil {
		t.Fatal(err)
	}

	// Simulate another replica already holding the reconcile lock.
	otherReplicaLock, acquired, err := valkeycache.AcquireLock(ctx, client, vkeys.OperationLock(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("test setup: expected to acquire the lock as the simulated other replica")
	}
	defer otherReplicaLock.Release(ctx)

	cfg := &config.Config{}
	if err := reconcileIndexIfEmpty(ctx, cfg, store, index, nil, client, vkeys); err != nil {
		t.Fatalf("reconcileIndexIfEmpty: %v", err)
	}

	entries, err := index.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no reconciliation to have run while another replica holds the lock, got entries: %v", entries)
	}
}

// TestReconcileIndexIfEmptyAcquiresLockAndReconciles proves the happy path
// with real Valkey-backed locking: with no contention, this replica
// acquires the lock, does the reconciliation, and releases it.
func TestReconcileIndexIfEmptyAcquiresLockAndReconciles(t *testing.T) {
	ctx := context.Background()
	client := testsupport.NewTestClient(t, testValkeyAddr)
	vkeys := valkeycache.Keys{Prefix: "reconcile-lock-test2:"}

	index := valkeystore.New(client, vkeys.Prefix)
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	debData := buildTestDeb(t, "recovered", "1.0")
	if err := store.PutFile(ctx, "pool/ubuntu/noble/some-upstream/main/r/recovered/recovered_1.0_amd64.deb", bytes.NewReader(debData), int64(len(debData))); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	if err := reconcileIndexIfEmpty(ctx, cfg, store, index, nil, client, vkeys); err != nil {
		t.Fatalf("reconcileIndexIfEmpty: %v", err)
	}

	entries, err := index.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "recovered" {
		t.Fatalf("expected the pool file to be reconciled, got %v", entries)
	}

	// The lock must have been released -- a fresh acquire should succeed.
	lock, acquired, err := valkeycache.AcquireLock(ctx, client, vkeys.OperationLock(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !acquired {
		t.Fatal("expected the reconcile lock to have been released after completion")
	}
	lock.Release(ctx)
}

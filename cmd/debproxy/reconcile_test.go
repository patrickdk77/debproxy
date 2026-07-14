package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/metadata/deb822store"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage/filesystem"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

// buildTestDeb creates a minimal .deb AR archive with the given
// package/version, readable by internal/deb.ControlParagraph -- adapted from
// internal/deb/control_test.go's buildDeb (each package that needs one keeps
// its own small copy rather than sharing a test-only helper package).
func buildTestDeb(t *testing.T, pkg, version string) []byte {
	t.Helper()
	control := []byte(fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\n", pkg, version))

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Size: int64(len(control)), Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(control); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeTestARMember(&ar, "debian-binary", []byte("2.0\n"))
	writeTestARMember(&ar, "control.tar", tarBuf.Bytes())
	writeTestARMember(&ar, "data.tar.gz", []byte{0x1f, 0x8b, 0x08, 0x00})
	return ar.Bytes()
}

func writeTestARMember(w *bytes.Buffer, name string, data []byte) {
	hdr := make([]byte, 60)
	copy(hdr[0:], name+"/")
	for i := len(name) + 1; i < 16; i++ {
		hdr[i] = ' '
	}
	copy(hdr[16:], "0           ")
	copy(hdr[28:], "0     ")
	copy(hdr[34:], "0     ")
	copy(hdr[40:], "100644  ")
	sz := len(data)
	copy(hdr[48:], fmt.Sprintf("%-10d", sz))
	hdr[58] = '`'
	hdr[59] = '\n'
	w.Write(hdr)
	w.Write(data)
	if sz%2 == 1 {
		w.WriteByte(0)
	}
}

// TestReconcileIndexIfEmptySkipsWhenIndexHasEntries proves the early-return
// gate: an index that already has entries must not be touched by a pool-walk
// reconciliation, even when the pool holds an unindexed file.
func TestReconcileIndexIfEmptySkipsWhenIndexHasEntries(t *testing.T) {
	ctx := context.Background()
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb822store.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := index.UpsertEntry(ctx, model.IndexEntry{
		OS: "ubuntu", Codename: "noble", Component: "main", Arch: "amd64",
		Package: "existing", Version: "1.0", PoolPath: "pool/ubuntu/noble/some-upstream/main/e/existing/existing_1.0_amd64.deb",
	}); err != nil {
		t.Fatal(err)
	}

	// An unindexed file sitting in the pool -- if reconciliation ran despite
	// the index being non-empty, this would get picked up too.
	debData := buildTestDeb(t, "unindexed", "1.0")
	if err := store.PutFile(ctx, "pool/ubuntu/noble/some-upstream/main/u/unindexed/unindexed_1.0_amd64.deb", bytes.NewReader(debData), int64(len(debData))); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	if err := reconcileIndexIfEmpty(ctx, cfg, store, index, nil, nil, valkeycache.Keys{}); err != nil {
		t.Fatalf("reconcileIndexIfEmpty: %v", err)
	}

	entries, err := index.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected the index to remain untouched (1 entry), got %d: %v", len(entries), entries)
	}
	if entries[0].Package != "existing" {
		t.Errorf("expected only the pre-existing entry, got %v", entries)
	}
}

// TestReconcileIndexIfEmptyReconcilesFromPoolWhenEmpty proves the actual
// recovery path: an empty index gets backfilled from whatever .deb files are
// still sitting in the pool.
func TestReconcileIndexIfEmptyReconcilesFromPoolWhenEmpty(t *testing.T) {
	ctx := context.Background()
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	index, err := deb822store.New(ctx, store)
	if err != nil {
		t.Fatal(err)
	}

	debData := buildTestDeb(t, "recovered", "1.0")
	if err := store.PutFile(ctx, "pool/ubuntu/noble/some-upstream/main/r/recovered/recovered_1.0_amd64.deb", bytes.NewReader(debData), int64(len(debData))); err != nil {
		t.Fatal(err)
	}

	// Empty config -- no upstream layouts to match, so the pool-walk's
	// on-demand-fetch fallback never fires a real network call (see
	// rebuild.lazyFetcher.lookup/ensureFetched): with no ResolvedLayouts,
	// nothing in cfg.ResolvedLayouts matches this file's upstream segment, so
	// it resolves via the "no known component" fallback instead.
	cfg := &config.Config{}
	if err := reconcileIndexIfEmpty(ctx, cfg, store, index, nil, nil, valkeycache.Keys{}); err != nil {
		t.Fatalf("reconcileIndexIfEmpty: %v", err)
	}

	entries, err := index.ListEntries(ctx, model.Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Package != "recovered" || entries[0].Version != "1.0" {
		t.Fatalf("expected the pool file to be reconciled into the index, got %v", entries)
	}
}

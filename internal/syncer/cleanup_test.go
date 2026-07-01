package syncer_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/syncer"
)

// ---------------------------------------------------------------------------
// Mock Storage
// ---------------------------------------------------------------------------

type mockStorage struct {
	// pool files: path -> content (empty string is fine)
	poolFiles map[string]struct{}

	// published files: path -> content (for OpenPublished)
	publishedFiles map[string]string

	// snapshots per osName
	snapshots map[string][]storage.SnapshotRef

	// deleted tracks Delete and DeletePublished calls
	deleted []string
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		poolFiles:      map[string]struct{}{},
		publishedFiles: map[string]string{},
		snapshots:      map[string][]storage.SnapshotRef{},
	}
}

func (m *mockStorage) WalkPool(ctx context.Context, fn func(string) error) error {
	for p := range m.poolFiles {
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockStorage) Delete(ctx context.Context, path string) error {
	delete(m.poolFiles, path)
	m.deleted = append(m.deleted, path)
	return nil
}

func (m *mockStorage) ListPublished(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	for p := range m.publishedFiles {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *mockStorage) OpenPublished(ctx context.Context, relPath string) (io.ReadCloser, error) {
	content, ok := m.publishedFiles[relPath]
	if !ok {
		return nil, fmt.Errorf("not found: %s", relPath)
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (m *mockStorage) DeletePublished(ctx context.Context, relPath string) error {
	delete(m.publishedFiles, relPath)
	m.deleted = append(m.deleted, relPath)
	return nil
}

func (m *mockStorage) ListSnapshots(ctx context.Context, osName string) ([]storage.SnapshotRef, error) {
	return m.snapshots[osName], nil
}

// Stubs for the remaining Storage interface methods.

func (m *mockStorage) PutFile(ctx context.Context, poolPath string, r io.Reader, size int64) error {
	panic("not implemented: PutFile")
}

func (m *mockStorage) Open(ctx context.Context, poolPath string) (io.ReadCloser, error) {
	panic("not implemented: Open")
}

func (m *mockStorage) Stat(ctx context.Context, poolPath string) (storage.FileInfo, error) {
	panic("not implemented: Stat")
}

func (m *mockStorage) Exists(ctx context.Context, poolPath string) (bool, error) {
	panic("not implemented: Exists")
}

func (m *mockStorage) ComputeChecksums(ctx context.Context, poolPath string) (model.Checksums, error) {
	panic("not implemented: ComputeChecksums")
}

func (m *mockStorage) WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error {
	panic("not implemented: WriteFile")
}

func (m *mockStorage) StatPublished(ctx context.Context, relPath string) (storage.FileInfo, error) {
	panic("not implemented: StatPublished")
}

func (m *mockStorage) ResolveSnapshot(ctx context.Context, osName string, at time.Time) (string, error) {
	panic("not implemented: ResolveSnapshot")
}

func (m *mockStorage) Ping(ctx context.Context) error { return nil }

// ---------------------------------------------------------------------------
// Mock MetadataIndex
// ---------------------------------------------------------------------------

type mockIndex struct {
	entries    []model.IndexEntry
	srcEntries []model.SourceEntry
}

func (m *mockIndex) ListEntries(ctx context.Context, sel model.Selector) ([]model.IndexEntry, error) {
	return m.entries, nil
}

func (m *mockIndex) ListSourceEntries(ctx context.Context, sel model.Selector) ([]model.SourceEntry, error) {
	return m.srcEntries, nil
}

// Stubs for the remaining MetadataIndex interface methods.

func (m *mockIndex) Ping(ctx context.Context) error                   { return nil }
func (m *mockIndex) Migrate(ctx context.Context) error                { return nil }
func (m *mockIndex) Reset(ctx context.Context) error                  { return nil }
func (m *mockIndex) Refresh(ctx context.Context) error                { return nil }
func (m *mockIndex) Flush(ctx context.Context) error                  { return nil }
func (m *mockIndex) UpsertEntry(ctx context.Context, entry model.IndexEntry) error {
	panic("not implemented: UpsertEntry")
}
func (m *mockIndex) EntryByDigest(ctx context.Context, digest model.Digest) (*model.IndexEntry, error) {
	panic("not implemented: EntryByDigest")
}
func (m *mockIndex) FindEntry(ctx context.Context, sel model.Selector, pkg, version string) (*model.IndexEntry, error) {
	panic("not implemented: FindEntry")
}
func (m *mockIndex) UpsertUpstreamState(ctx context.Context, state model.UpstreamPackageState) error {
	panic("not implemented: UpsertUpstreamState")
}
func (m *mockIndex) GetUpstreamState(ctx context.Context, upstream, name, arch string) (*model.UpstreamPackageState, error) {
	panic("not implemented: GetUpstreamState")
}
func (m *mockIndex) UpsertSourceEntry(ctx context.Context, entry model.SourceEntry) error {
	panic("not implemented: UpsertSourceEntry")
}
func (m *mockIndex) FindSourceEntry(ctx context.Context, sel model.Selector, pkg, version string) (*model.SourceEntry, error) {
	panic("not implemented: FindSourceEntry")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// minimalConfig returns a *config.Config with a single resolved layout for
// the given OS/codename so that osNames() returns the expected value.
func minimalConfig(osName, codename string) *config.Config {
	return &config.Config{
		ResolvedLayouts: []model.Layout{
			{
				OS:        osName,
				Codename:  codename,
				Component: "main",
				Archs:     []string{"amd64"},
			},
		},
	}
}

// newTestSyncer builds a *Syncer backed by mock storage and index.
func newTestSyncer(store *mockStorage, idx *mockIndex, osName, codename string) *syncer.Syncer {
	cfg := minimalConfig(osName, codename)
	return syncer.New(cfg, store, idx, nil, nil, nil, nil)
}

func contains(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tests: pruneSnapshots
// ---------------------------------------------------------------------------

func TestPruneSnapshots_ZeroLimits(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// Add several old snapshots.
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-1", OS: "ubuntu", CreatedAt: now.Add(-100 * 24 * time.Hour)},
		{ID: "snap-2", OS: "ubuntu", CreatedAt: now.Add(-50 * 24 * time.Hour)},
	}
	// Add published files so DeletePublished would be called if pruning happened.
	store.publishedFiles["snap-1/ubuntu/dists/jammy/Release"] = "content"
	store.publishedFiles["snap-2/ubuntu/dists/jammy/Release"] = "content"

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(store.deleted) != 0 {
		t.Errorf("expected no deletions with zero limits, got %v", store.deleted)
	}
}

// pruneSnapshots is called via Cleanup; we call it indirectly.
// Use a helper that calls the full Cleanup to exercise pruneSnapshots.

func TestPruneSnapshots_CountWithinLimit(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// 2 snapshots, limit is 5  -- count within limit so no pruning.
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-old", OS: "ubuntu", CreatedAt: now.Add(-200 * 24 * time.Hour)},
		{ID: "snap-new", OS: "ubuntu", CreatedAt: now.Add(-10 * 24 * time.Hour)},
	}
	store.publishedFiles["snap-old/ubuntu/dists/jammy/Release"] = "content"
	store.publishedFiles["snap-new/ubuntu/dists/jammy/Release"] = "content"

	if err := s.Cleanup(context.Background(), 5, 30*24*time.Hour, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}
	if len(store.deleted) != 0 {
		t.Errorf("expected no deletions when count is within limit, got %v", store.deleted)
	}
}

func TestPruneSnapshots_CountExceedsButAgeTooYoung(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// 3 snapshots, limit is 2  -- count exceeds, but oldest is only 5 days old.
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-a", OS: "ubuntu", CreatedAt: now.Add(-5 * 24 * time.Hour)},
		{ID: "snap-b", OS: "ubuntu", CreatedAt: now.Add(-3 * 24 * time.Hour)},
		{ID: "snap-c", OS: "ubuntu", CreatedAt: now.Add(-1 * 24 * time.Hour)},
	}
	for _, id := range []string{"snap-a", "snap-b", "snap-c"} {
		store.publishedFiles[id+"/ubuntu/dists/jammy/Release"] = "content"
	}

	// Age limit is 30 days; oldest is only 5 days  -- no deletion expected.
	if err := s.Cleanup(context.Background(), 2, 30*24*time.Hour, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}
	if len(store.deleted) != 0 {
		t.Errorf("expected no deletions when age is too young, got %v", store.deleted)
	}
}

func TestPruneSnapshots_CountAndAgeExceed(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// 3 snapshots, keep limit = 2, age limit = 30 days.
	// snap-old is 100 days old  -- should be deleted.
	// snap-mid is 20 days old  -- within age limit so stays, but it is at index 1 (0-based
	//   after sort newest-first: snap-new idx=0, snap-mid idx=1, snap-old idx=2).
	//   Index >= maxSnapshots(2) AND age > 30d  -- only snap-old qualifies.
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-old", OS: "ubuntu", CreatedAt: now.Add(-100 * 24 * time.Hour)},
		{ID: "snap-mid", OS: "ubuntu", CreatedAt: now.Add(-20 * 24 * time.Hour)},
		{ID: "snap-new", OS: "ubuntu", CreatedAt: now.Add(-1 * 24 * time.Hour)},
	}
	store.publishedFiles["snap-old/ubuntu/dists/jammy/Release"] = "old-content"
	store.publishedFiles["snap-mid/ubuntu/dists/jammy/Release"] = "mid-content"
	store.publishedFiles["snap-new/ubuntu/dists/jammy/Release"] = "new-content"

	if err := s.Cleanup(context.Background(), 2, 30*24*time.Hour, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, "snap-old/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-old file to be deleted, deleted=%v", store.deleted)
	}
	if contains(store.deleted, "snap-mid/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-mid file to be kept, deleted=%v", store.deleted)
	}
	if contains(store.deleted, "snap-new/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-new file to be kept, deleted=%v", store.deleted)
	}
}

func TestPruneSnapshots_DeletedCountMatchesDeleted(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// 4 snapshots, keep 1, age limit 10 days  -- 3 oldest qualify (each > 10 days old).
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-1", OS: "ubuntu", CreatedAt: now.Add(-90 * 24 * time.Hour)},
		{ID: "snap-2", OS: "ubuntu", CreatedAt: now.Add(-60 * 24 * time.Hour)},
		{ID: "snap-3", OS: "ubuntu", CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ID: "snap-4", OS: "ubuntu", CreatedAt: now.Add(-1 * 24 * time.Hour)},
	}
	// Add at least one published file per snapshot so DeletePublished fires.
	for _, id := range []string{"snap-1", "snap-2", "snap-3", "snap-4"} {
		store.publishedFiles[id+"/ubuntu/dists/jammy/Release"] = "content"
	}

	if err := s.Cleanup(context.Background(), 1, 10*24*time.Hour, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	// snap-1, snap-2, snap-3 should each have had their published file deleted.
	wantDeleted := []string{
		"snap-1/ubuntu/dists/jammy/Release",
		"snap-2/ubuntu/dists/jammy/Release",
		"snap-3/ubuntu/dists/jammy/Release",
	}
	for _, path := range wantDeleted {
		if !contains(store.deleted, path) {
			t.Errorf("expected %q to be deleted, deleted=%v", path, store.deleted)
		}
	}
	if contains(store.deleted, "snap-4/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-4 to be kept, deleted=%v", store.deleted)
	}
}

// ---------------------------------------------------------------------------
// Tests: gcPool
// ---------------------------------------------------------------------------

func TestGCPool_ReferencedByPackagesIndex_Kept(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	poolFile := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[poolFile] = struct{}{}

	// Publish a Packages file that references the pool file.
	packagesContent := "Package: libfoo\nVersion: 1.0\nFilename: " + poolFile + "\n\n"
	pkgPath := "current/ubuntu/dists/jammy/main/binary-amd64/Packages"
	store.publishedFiles[pkgPath] = packagesContent

	// No snapshots, so only "current" prefix is scanned.
	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, poolFile) {
		t.Errorf("pool file referenced by Packages index should not be deleted")
	}
}

func TestGCPool_ReferencedByMetadataEntry_Kept(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{
		entries: []model.IndexEntry{
			{PoolPath: "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"},
		},
	}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	poolFile := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[poolFile] = struct{}{}

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, poolFile) {
		t.Errorf("pool file referenced by metadata entry should not be deleted")
	}
}

func TestGCPool_NotReferenced_Deleted(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	orphan := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[orphan] = struct{}{}

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, orphan) {
		t.Errorf("orphaned pool file should have been deleted, deleted=%v", store.deleted)
	}
}

func TestGCPool_EmptyPool_NothingDeleted(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(store.deleted) != 0 {
		t.Errorf("expected no deletions for empty pool, got %v", store.deleted)
	}
}

func TestGCPool_SnapshotPackagesIndex_Protects(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	poolFile := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_2.0_amd64.deb"
	store.poolFiles[poolFile] = struct{}{}

	snapID := "2024-01-01T00-00-00"
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: snapID, OS: "ubuntu", CreatedAt: time.Now().Add(-10 * 24 * time.Hour)},
	}

	// The snapshot has a Packages file referencing our pool file.
	packagesContent := "Package: libfoo\nVersion: 2.0\nFilename: " + poolFile + "\n\n"
	pkgPath := snapID + "/ubuntu/dists/jammy/main/binary-amd64/Packages"
	store.publishedFiles[pkgPath] = packagesContent

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, poolFile) {
		t.Errorf("pool file referenced by snapshot Packages index should not be deleted")
	}
}

// ---------------------------------------------------------------------------
// Tests: gcSrc
// ---------------------------------------------------------------------------

func TestGCSrc_ReferencedBySourcesIndex_Kept(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	srcFile := "src/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0.tar.gz"
	store.publishedFiles[srcFile] = "tarball-data"

	// Build a Sources index that references srcFile.
	// Directory is the dir part, Files section lists the filename.
	sourcesContent := "Package: libfoo\nVersion: 1.0\nDirectory: src/ubuntu/jammy/upstream/main/l/libfoo\nFiles:\n abc123 1024 libfoo_1.0.tar.gz\n\n"
	srcIndexPath := "current/ubuntu/dists/jammy/main/source/Sources"
	store.publishedFiles[srcIndexPath] = sourcesContent

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, srcFile) {
		t.Errorf("src file referenced by Sources index should not be deleted")
	}
}

func TestGCSrc_ReferencedByMetadataSourceEntry_Kept(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{
		srcEntries: []model.SourceEntry{
			{
				LocalDir: "src/ubuntu/jammy/upstream/main/l/libfoo",
				Files:    []model.SourceFile{{Filename: "libfoo_1.0.tar.gz"}},
			},
		},
	}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	srcFile := "src/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0.tar.gz"
	store.publishedFiles[srcFile] = "tarball-data"

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, srcFile) {
		t.Errorf("src file referenced by metadata source entry should not be deleted")
	}
}

func TestGCSrc_NotReferenced_Deleted(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	orphan := "src/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0.orig.tar.gz"
	store.publishedFiles[orphan] = "orphan-data"

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, orphan) {
		t.Errorf("orphaned src file should have been deleted, deleted=%v", store.deleted)
	}
}

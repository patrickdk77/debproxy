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

	// poolMTimes: path -> mod time, consulted by Stat. A path with no entry
	// here gets the zero Time (always older than gcGracePeriod), so existing
	// tests that expect immediate GC deletion don't need to set this.
	poolMTimes map[string]time.Time

	// snapshots per osName
	snapshots map[string][]storage.SnapshotRef

	// deleted tracks Delete and DeletePublished calls
	deleted []string

	// statCalls counts Stat invocations, so tests can assert gcPool/gcSrc
	// don't issue a redundant per-candidate Stat now that WalkPool/
	// ListPublishedInfo supply ModTime directly.
	statCalls int

	// existsErr, when set, is returned by every Exists call -- see Exists.
	existsErr error
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		poolFiles:      map[string]struct{}{},
		publishedFiles: map[string]string{},
		poolMTimes:     map[string]time.Time{},
		snapshots:      map[string][]storage.SnapshotRef{},
	}
}

func (m *mockStorage) WalkPool(ctx context.Context, fn func(storage.FileInfo) error) error {
	for p := range m.poolFiles {
		if err := fn(storage.FileInfo{Path: p, ModTime: m.poolMTimes[p]}); err != nil {
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

func (m *mockStorage) ListPublishedInfo(ctx context.Context, prefix string) ([]storage.FileInfo, error) {
	var out []storage.FileInfo
	for p := range m.publishedFiles {
		if strings.HasPrefix(p, prefix) {
			out = append(out, storage.FileInfo{Path: p, ModTime: m.poolMTimes[p]})
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

// Stat looks in both poolFiles and publishedFiles since tests store src/
// files (which real backends treat as part of the same non-published tree)
// under publishedFiles. Files with no explicit mtime set in poolMTimes
// default to the zero Time, which is always older than gcGracePeriod, so
// existing tests that expect immediate deletion keep working unmodified.
func (m *mockStorage) Stat(ctx context.Context, poolPath string) (storage.FileInfo, error) {
	m.statCalls++
	if _, ok := m.poolFiles[poolPath]; ok {
		return storage.FileInfo{Path: poolPath, ModTime: m.poolMTimes[poolPath]}, nil
	}
	if _, ok := m.publishedFiles[poolPath]; ok {
		return storage.FileInfo{Path: poolPath, ModTime: m.poolMTimes[poolPath]}, nil
	}
	return storage.FileInfo{}, fmt.Errorf("not found: %s", poolPath)
}

// Exists checks both poolFiles and publishedFiles, mirroring Stat's own
// lookup (see its comment) -- src/ files live in publishedFiles in this mock.
// If existsErr is set, it's returned unconditionally instead, simulating a
// real storage failure (outage, misconfiguration) rather than a hit/miss.
func (m *mockStorage) Exists(ctx context.Context, poolPath string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	if _, ok := m.poolFiles[poolPath]; ok {
		return true, nil
	}
	if _, ok := m.publishedFiles[poolPath]; ok {
		return true, nil
	}
	return false, nil
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

func (m *mockIndex) Ping(ctx context.Context) error    { return nil }
func (m *mockIndex) Migrate(ctx context.Context) error { return nil }
func (m *mockIndex) Reset(ctx context.Context) error   { return nil }
func (m *mockIndex) Refresh(ctx context.Context) error { return nil }
func (m *mockIndex) Flush(ctx context.Context) error   { return nil }
func (m *mockIndex) UpsertEntry(ctx context.Context, entry model.IndexEntry) error {
	panic("not implemented: UpsertEntry")
}
func (m *mockIndex) RemoveEntry(ctx context.Context, entry model.IndexEntry) error {
	for i, e := range m.entries {
		if e.OS == entry.OS && e.Codename == entry.Codename && e.Component == entry.Component &&
			e.Arch == entry.Arch && e.Package == entry.Package && e.Version == entry.Version {
			m.entries = append(m.entries[:i:i], m.entries[i+1:]...)
			return nil
		}
	}
	return nil
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
func (m *mockIndex) RemoveSourceEntry(ctx context.Context, entry model.SourceEntry) error {
	for i, e := range m.srcEntries {
		if e.OS == entry.OS && e.Codename == entry.Codename && e.Component == entry.Component &&
			e.Package == entry.Package && e.Version == entry.Version {
			m.srcEntries = append(m.srcEntries[:i:i], m.srcEntries[i+1:]...)
			return nil
		}
	}
	return nil
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

// newTestSyncerWithGCGrace is like newTestSyncer but with a custom
// schedule.gc_grace value.
func newTestSyncerWithGCGrace(store *mockStorage, idx *mockIndex, osName, codename, gcGrace string) *syncer.Syncer {
	cfg := minimalConfig(osName, codename)
	cfg.Schedule.GCGrace = gcGrace
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

func TestPruneSnapshotsZeroLimits(t *testing.T) {
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

func TestPruneSnapshotsCountWithinLimit(t *testing.T) {
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

func TestPruneSnapshotsCountExceedsButAgeTooYoung(t *testing.T) {
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

func TestPruneSnapshotsCountAndAgeExceed(t *testing.T) {
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

func TestPruneSnapshotsDeletedCountMatchesDeleted(t *testing.T) {
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

func TestPruneSnapshotsAgeOnlyCountUnlimited(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// maxSnapshots=0 (unlimited count): only the age axis should matter.
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-old", OS: "ubuntu", CreatedAt: now.Add(-100 * 24 * time.Hour)},
		{ID: "snap-new", OS: "ubuntu", CreatedAt: now.Add(-1 * 24 * time.Hour)},
	}
	store.publishedFiles["snap-old/ubuntu/dists/jammy/Release"] = "old-content"
	store.publishedFiles["snap-new/ubuntu/dists/jammy/Release"] = "new-content"

	if err := s.Cleanup(context.Background(), 0, 30*24*time.Hour, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, "snap-old/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-old to be pruned by age alone, deleted=%v", store.deleted)
	}
	if contains(store.deleted, "snap-new/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-new to be kept, deleted=%v", store.deleted)
	}
}

func TestPruneSnapshotsCountOnlyAgeUnlimited(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	// maxSnapshotAge=0 (unlimited age): only the count axis should matter.
	// All snapshots are recent, but the count limit of 1 should still prune down to it.
	store.snapshots["ubuntu"] = []storage.SnapshotRef{
		{ID: "snap-a", OS: "ubuntu", CreatedAt: now.Add(-3 * time.Hour)},
		{ID: "snap-b", OS: "ubuntu", CreatedAt: now.Add(-2 * time.Hour)},
		{ID: "snap-c", OS: "ubuntu", CreatedAt: now.Add(-1 * time.Hour)},
	}
	for _, id := range []string{"snap-a", "snap-b", "snap-c"} {
		store.publishedFiles[id+"/ubuntu/dists/jammy/Release"] = "content"
	}

	if err := s.Cleanup(context.Background(), 1, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, "snap-a/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-a to be pruned by count alone, deleted=%v", store.deleted)
	}
	if !contains(store.deleted, "snap-b/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-b to be pruned by count alone, deleted=%v", store.deleted)
	}
	if contains(store.deleted, "snap-c/ubuntu/dists/jammy/Release") {
		t.Errorf("expected snap-c (most recent) to be kept, deleted=%v", store.deleted)
	}
}

// ---------------------------------------------------------------------------
// Tests: gcPool
// ---------------------------------------------------------------------------

func TestGCPoolReferencedByPackagesIndexKept(t *testing.T) {
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

func TestGCPoolReferencedByMetadataEntryKept(t *testing.T) {
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

// TestGCPool_SupersededVersion_NotProtected proves that once a newer version
// of a package is indexed, the pool file for the OLD version is no longer
// protected from GC forever -- buildPoolRefSet must only keep the highest
// version per (os, codename, component, arch, package), matching the same
// dedup publishing already applies (groupStanzas in syncer.go).
func TestGCPoolSupersededVersionNotProtected(t *testing.T) {
	store := newMockStorage()
	oldPath := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	newPath := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_2.0_amd64.deb"
	idx := &mockIndex{
		entries: []model.IndexEntry{
			{OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64", Package: "libfoo", Version: "1.0", PoolPath: oldPath},
			{OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64", Package: "libfoo", Version: "2.0", PoolPath: newPath},
		},
	}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	store.poolFiles[oldPath] = struct{}{}
	store.poolFiles[newPath] = struct{}{}
	now := time.Now()
	store.poolMTimes[oldPath] = now.Add(-2 * time.Hour) // past the GC grace period
	store.poolMTimes[newPath] = now.Add(-2 * time.Hour)

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, oldPath) {
		t.Errorf("superseded version's pool file should be GC'd once a newer version is indexed, deleted=%v", store.deleted)
	}
	if contains(store.deleted, newPath) {
		t.Errorf("current version's pool file must not be deleted, deleted=%v", store.deleted)
	}
}

// TestCleanup_GCDoesNotCallStat proves gcPool/gcSrc get ModTime from
// WalkPool/ListPublishedInfo directly instead of issuing a separate Stat per
// orphan candidate.
func TestCleanupGCDoesNotCallStat(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	orphanPool := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	orphanSrc := "src/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0.orig.tar.gz"
	store.poolFiles[orphanPool] = struct{}{}
	store.publishedFiles[orphanSrc] = "orphan-data"

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, orphanPool) || !contains(store.deleted, orphanSrc) {
		t.Fatalf("test setup: expected both orphans deleted, deleted=%v", store.deleted)
	}
	if store.statCalls != 0 {
		t.Errorf("expected zero Stat calls during GC, got %d", store.statCalls)
	}
}

func TestGCPoolNotReferencedDeleted(t *testing.T) {
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

// TestGCPool_RecentlyWritten_ProtectedByGracePeriod proves the TOCTOU fix:
// a pool file that isn't in the ref set yet (e.g. because the metadata index
// commit for it hasn't landed) but was written moments ago must survive a GC
// pass instead of being deleted right after being cached.
func TestGCPoolRecentlyWrittenProtectedByGracePeriod(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	recent := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[recent] = struct{}{}
	now := time.Now()
	store.poolMTimes[recent] = now.Add(-1 * time.Minute) // written 1 minute ago

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, recent) {
		t.Errorf("recently-written unreferenced pool file should be protected by the grace period, deleted=%v", store.deleted)
	}
}

// TestGCPool_OldUnreferenced_DeletedPastGracePeriod is the control case: once
// a file is older than gcGracePeriod, an unreferenced file is still deleted.
func TestGCPoolOldUnreferencedDeletedPastGracePeriod(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	orphan := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[orphan] = struct{}{}
	now := time.Now()
	store.poolMTimes[orphan] = now.Add(-2 * time.Hour) // well past the grace period

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, orphan) {
		t.Errorf("orphaned pool file older than the grace period should still be deleted, deleted=%v", store.deleted)
	}
}

// TestGCPool_GCGraceConfigurable proves schedule.gc_grace actually changes GC
// behavior: a file older than a configured 1ms grace period (but younger than
// the 1h built-in default) is deleted.
func TestGCPoolGCGraceConfigurable(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncerWithGCGrace(store, idx, "ubuntu", "jammy", "1ms")

	orphan := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[orphan] = struct{}{}
	now := time.Now()
	store.poolMTimes[orphan] = now.Add(-10 * time.Millisecond) // > 1ms configured grace, < 1h default

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if !contains(store.deleted, orphan) {
		t.Errorf("file older than the configured 1ms grace period should be deleted, deleted=%v", store.deleted)
	}
}

// TestGCPool_GCGraceInvalidFallsBackToDefault proves an unparseable
// schedule.gc_grace value falls back to the safe 1h default rather than
// disabling grace-period protection entirely.
func TestGCPoolGCGraceInvalidFallsBackToDefault(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncerWithGCGrace(store, idx, "ubuntu", "jammy", "not-a-duration")

	recent := "pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_1.0_amd64.deb"
	store.poolFiles[recent] = struct{}{}
	now := time.Now()
	store.poolMTimes[recent] = now.Add(-10 * time.Minute) // within the 1h default

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if contains(store.deleted, recent) {
		t.Errorf("invalid schedule.gc_grace should fall back to the 1h default, not disable protection, deleted=%v", store.deleted)
	}
}

func TestGCPoolEmptyPoolNothingDeleted(t *testing.T) {
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

func TestGCPoolSnapshotPackagesIndexProtects(t *testing.T) {
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

func TestGCSrcReferencedBySourcesIndexKept(t *testing.T) {
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

func TestGCSrcReferencedByMetadataSourceEntryKept(t *testing.T) {
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

// ---------------------------------------------------------------------------
// Tests: orphan-ratio safety check (checkOrphanRatio)
// ---------------------------------------------------------------------------

// TestGCPoolAbortsWhenOrphanRatioImplausiblyHigh is the regression test for
// the actual incident: a broken/empty reference set (metadata index and
// snapshots both empty) must not be allowed to delete a large, otherwise-
// healthy pool. Below minFilesForRatioCheck this can't be distinguished from
// routine small-scale GC, so the pool here is well above that floor.
func TestGCPoolAbortsWhenOrphanRatioImplausiblyHigh(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{} // empty index -- nothing protected
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	now := time.Now()
	for i := 0; i < 60; i++ {
		path := fmt.Sprintf("pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo_%d.0_amd64.deb", i)
		store.poolFiles[path] = struct{}{}
		store.poolMTimes[path] = now.Add(-2 * time.Hour) // past grace period
	}

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(store.deleted) != 0 {
		t.Errorf("expected GC to abort rather than delete a mostly-orphaned pool, but deleted %d files: %v", len(store.deleted), store.deleted)
	}
}

// TestGCPoolProceedsWhenOrphanRatioBelowThreshold proves the safety check
// doesn't block ordinary GC: a small tail of genuinely superseded/orphaned
// files among a large, mostly-referenced pool should still be deleted.
func TestGCPoolProceedsWhenOrphanRatioBelowThreshold(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	var entries []model.IndexEntry
	for i := 0; i < 50; i++ {
		path := fmt.Sprintf("pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo-keep-%d_1.0_amd64.deb", i)
		store.poolFiles[path] = struct{}{}
		store.poolMTimes[path] = now.Add(-2 * time.Hour)
		entries = append(entries, model.IndexEntry{
			OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
			Package: fmt.Sprintf("libfoo-keep-%d", i), Version: "1.0", PoolPath: path,
		})
	}
	idx.entries = entries
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	// A small number of genuinely orphaned files -- well under maxOrphanRatio
	// of the total 60 files scanned.
	var orphans []string
	for i := 0; i < 10; i++ {
		path := fmt.Sprintf("pool/ubuntu/jammy/upstream/main/l/libfoo/libfoo-orphan-%d_1.0_amd64.deb", i)
		store.poolFiles[path] = struct{}{}
		store.poolMTimes[path] = now.Add(-2 * time.Hour)
		orphans = append(orphans, path)
	}

	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	for _, path := range orphans {
		if !contains(store.deleted, path) {
			t.Errorf("expected genuinely orphaned file %q to be deleted when orphan ratio is low, deleted=%v", path, store.deleted)
		}
	}
	if len(store.deleted) != len(orphans) {
		t.Errorf("expected exactly %d deletions, got %d: %v", len(orphans), len(store.deleted), store.deleted)
	}
}

// TestGCSrcAbortsWhenOrphanRatioImplausiblyHigh is gcSrc's counterpart to
// TestGCPoolAbortsWhenOrphanRatioImplausiblyHigh.
func TestGCSrcAbortsWhenOrphanRatioImplausiblyHigh(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	s := newTestSyncer(store, idx, "ubuntu", "jammy")

	for i := 0; i < 60; i++ {
		path := fmt.Sprintf("src/ubuntu/jammy/upstream/main/l/libfoo/libfoo_%d.0.orig.tar.gz", i)
		store.publishedFiles[path] = "data"
	}

	if err := s.Cleanup(context.Background(), 0, 0, time.Now()); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(store.deleted) != 0 {
		t.Errorf("expected src GC to abort rather than delete a mostly-orphaned tree, but deleted %d files: %v", len(store.deleted), store.deleted)
	}
}

func TestGCSrcNotReferencedDeleted(t *testing.T) {
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

// ---------------------------------------------------------------------------
// Tests: pruneMissingEntries / pruneMissingSrcEntries
//
// These are the reverse direction of gcPool/gcSrc: an entry whose pool/src
// file no longer exists (an out-of-band deletion, a prior GC incident) must
// be removed from the index, or pull-through's self-heal is permanently
// defeated (Ingestor.Cache trusts its ExistsCache, seeded from these same
// entries, and never re-downloads a file it believes already exists).
// ---------------------------------------------------------------------------

func TestCleanupRemovesEntryForMissingPoolFile(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	gone := model.IndexEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
		Package: "vanished", Version: "1.0",
		PoolPath: "pool/ubuntu/jammy/upstream/main/v/vanished/vanished_1.0_amd64.deb",
		FirstSeen: now.Add(-2 * time.Hour), // past the grace period
	}
	idx.entries = []model.IndexEntry{gone}
	// Deliberately not adding gone.PoolPath to store.poolFiles -- it's gone.

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.entries) != 0 {
		t.Errorf("expected entry for missing pool file to be removed, got %v", idx.entries)
	}
}

func TestCleanupKeepsEntryForExistingPoolFile(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	present := model.IndexEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
		Package: "curl", Version: "8.0",
		PoolPath:  "pool/ubuntu/jammy/upstream/main/c/curl/curl_8.0_amd64.deb",
		FirstSeen: now.Add(-2 * time.Hour),
	}
	idx.entries = []model.IndexEntry{present}
	store.poolFiles[present.PoolPath] = struct{}{}
	store.poolMTimes[present.PoolPath] = now.Add(-2 * time.Hour)

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.entries) != 1 {
		t.Errorf("expected entry with an existing pool file to survive, got %v", idx.entries)
	}
}

// TestCleanupRecentMissingEntryProtectedByGracePeriod mirrors
// TestGCPoolRecentlyWrittenProtectedByGracePeriod: an entry created moments
// ago must not be pruned just because its file isn't visible yet, in case a
// storage backend's read-after-write isn't instantaneous.
func TestCleanupRecentMissingEntryProtectedByGracePeriod(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	recent := model.IndexEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
		Package: "fresh", Version: "1.0",
		PoolPath:  "pool/ubuntu/jammy/upstream/main/f/fresh/fresh_1.0_amd64.deb",
		FirstSeen: now.Add(-1 * time.Minute), // within the 1h default grace period
	}
	idx.entries = []model.IndexEntry{recent}

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.entries) != 1 {
		t.Errorf("expected recently-created entry to be protected by the grace period, got %v", idx.entries)
	}
}

// TestCleanupAbortsMissingEntryPruneWhenRatioImplausiblyHigh is the same
// safety net as TestGCPoolAbortsWhenOrphanRatioImplausiblyHigh, applied to
// the reverse direction: if store.Exists reports most entries' files gone,
// that's overwhelmingly a sign store.Exists itself is broken (wrong bucket/
// mount, an outage), not that the pool was actually wiped -- must abort
// rather than empty out the whole metadata index.
func TestCleanupAbortsMissingEntryPruneWhenRatioImplausiblyHigh(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	var entries []model.IndexEntry
	for i := 0; i < 60; i++ {
		entries = append(entries, model.IndexEntry{
			OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
			Package: fmt.Sprintf("pkg-%d", i), Version: "1.0",
			PoolPath:  fmt.Sprintf("pool/ubuntu/jammy/upstream/main/p/pkg-%d/pkg-%d_1.0_amd64.deb", i, i),
			FirstSeen: now.Add(-2 * time.Hour),
		})
	}
	idx.entries = entries
	// None of these pool files exist in store.poolFiles.

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.entries) != len(entries) {
		t.Errorf("expected missing-entry prune to abort and remove nothing, got %d of %d entries remaining", len(idx.entries), len(entries))
	}
}

// TestCleanupPruneMissingEntriesPropagatesStoreExistsError is the error-state
// counterpart to the happy-path tests above: a real storage failure while
// checking file existence must fail Cleanup, not be swallowed into "file
// doesn't exist" (which would wrongly remove entries whose files are fine
// but merely unreachable at that moment).
func TestCleanupPruneMissingEntriesPropagatesStoreExistsError(t *testing.T) {
	store := newMockStorage()
	store.existsErr = fmt.Errorf("simulated storage outage")
	idx := &mockIndex{}
	now := time.Now()

	idx.entries = []model.IndexEntry{{
		OS: "ubuntu", Codename: "jammy", Component: "main", Arch: "amd64",
		Package: "curl", Version: "8.0",
		PoolPath:  "pool/ubuntu/jammy/upstream/main/c/curl/curl_8.0_amd64.deb",
		FirstSeen: now.Add(-2 * time.Hour),
	}}

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err == nil {
		t.Fatal("expected Cleanup to fail when store.Exists errors, got nil")
	}
	if len(idx.entries) != 1 {
		t.Errorf("expected entry untouched when store.Exists errors, got %v", idx.entries)
	}
}

func TestCleanupRemovesSrcEntryForMissingFile(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	gone := model.SourceEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main",
		Package: "vanished", Version: "1.0",
		LocalDir:        "src/ubuntu/jammy/upstream/main/v/vanished",
		Files:           []model.SourceFile{{Filename: "vanished_1.0.dsc"}},
		FilesDownloaded: true,
		FirstSeen:       now.Add(-2 * time.Hour),
	}
	idx.srcEntries = []model.SourceEntry{gone}
	// Deliberately not adding the file to store.publishedFiles -- it's gone.

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.srcEntries) != 0 {
		t.Errorf("expected src entry for missing file to be removed, got %v", idx.srcEntries)
	}
}

// TestCleanupSkipsSrcEntryNotYetDownloaded proves FilesDownloaded=false
// entries are left alone even though their (never-fetched) files obviously
// aren't in storage -- there's nothing to reconcile for a source package
// whose files were never claimed to be cached locally in the first place.
func TestCleanupSkipsSrcEntryNotYetDownloaded(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	notDownloaded := model.SourceEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main",
		Package: "neverfetched", Version: "1.0",
		LocalDir:        "src/ubuntu/jammy/upstream/main/n/neverfetched",
		Files:           []model.SourceFile{{Filename: "neverfetched_1.0.dsc"}},
		FilesDownloaded: false,
		FirstSeen:       now.Add(-2 * time.Hour),
	}
	idx.srcEntries = []model.SourceEntry{notDownloaded}

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.srcEntries) != 1 {
		t.Errorf("expected not-yet-downloaded src entry to be left alone, got %v", idx.srcEntries)
	}
}

// TestCleanupRemovesSrcEntryWhenAnyFileMissing proves a source entry with
// several files is removed if even one is gone -- FilesDownloaded is a
// single flag, not tracked per file, so a partial loss already makes its
// "files are downloaded" claim false.
func TestCleanupRemovesSrcEntryWhenAnyFileMissing(t *testing.T) {
	store := newMockStorage()
	idx := &mockIndex{}
	now := time.Now()

	partial := model.SourceEntry{
		OS: "ubuntu", Codename: "jammy", Component: "main",
		Package: "partial", Version: "1.0",
		LocalDir: "src/ubuntu/jammy/upstream/main/p/partial",
		Files: []model.SourceFile{
			{Filename: "partial_1.0.dsc"},
			{Filename: "partial_1.0.orig.tar.gz"},
		},
		FilesDownloaded: true,
		FirstSeen:       now.Add(-2 * time.Hour),
	}
	idx.srcEntries = []model.SourceEntry{partial}
	// Only one of the two files still exists.
	store.publishedFiles[partial.LocalDir+"/partial_1.0.dsc"] = "data"

	s := newTestSyncer(store, idx, "ubuntu", "jammy")
	if err := s.Cleanup(context.Background(), 0, 0, now); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if len(idx.srcEntries) != 0 {
		t.Errorf("expected src entry with a partially-missing file set to be removed, got %v", idx.srcEntries)
	}
}

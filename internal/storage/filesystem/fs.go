package filesystem

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

// Store implements filesystem-backed pool and snapshot trees.
type Store struct {
	root     string
	poolRoot string
}

// New creates a filesystem storage backend.
func New(root string) (*Store, error) {
	s := &Store{
		root:     root,
		poolRoot: filepath.Join(root, "pool"),
	}
	for _, dir := range []string{s.root, s.poolRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	return s, nil
}

func (s *Store) Ping(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if _, err := os.Stat(s.root); err != nil {
		return err
	}
	return nil
}

func (s *Store) absPool(poolPath string) (string, error) {
	clean, err := storage.CleanRelPath(poolPath)
	if err != nil {
		return "", fmt.Errorf("invalid pool path %q", poolPath)
	}
	clean = strings.TrimPrefix(clean, "pool/")
	return filepath.Join(s.poolRoot, filepath.FromSlash(clean)), nil
}

func (s *Store) absPublished(relPath string) (string, error) {
	clean, err := storage.CleanRelPath(relPath)
	if err != nil {
		return "", fmt.Errorf("invalid published path %q", relPath)
	}
	return filepath.Join(s.root, filepath.FromSlash(clean)), nil
}

// PutFile stores content at poolPath and writes it atomically with temp+rename.
func (s *Store) PutFile(ctx context.Context, poolPath string, r io.Reader, size int64) error {
	abs, err := s.absPool(poolPath)
	if err != nil {
		return err
	}
	if exists, err := s.Exists(ctx, poolPath); err != nil {
		return err
	} else if exists {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	// Write directly into the natural pool path using an atomic temp+rename
	// in the destination directory. Content-level dedup is the responsibility
	// of the metadata index (sha256 -> canonical pool_path) per PLAN.md.
	dir := filepath.Dir(abs)
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	// Attempt to atomically move into place. If the path already exists,
	// keep-first-wins semantics: leave existing file and remove the temp.
	if err := os.Rename(tmpPath, abs); err != nil {
		if os.IsExist(err) {
			return nil
		}
		// If rename fails because dst exists, treat as success. For other
		// errors, return them.
		if _, statErr := os.Stat(abs); statErr == nil {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) Open(ctx context.Context, poolPath string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := s.absPool(poolPath)
	if err != nil {
		return nil, err
	}
	return os.Open(abs)
}

func (s *Store) Stat(ctx context.Context, poolPath string) (storage.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return storage.FileInfo{}, err
	}
	abs, err := s.absPool(poolPath)
	if err != nil {
		return storage.FileInfo{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return storage.FileInfo{}, err
	}
	return storage.FileInfo{Path: poolPath, Size: st.Size(), ModTime: st.ModTime()}, nil
}

func (s *Store) Exists(ctx context.Context, poolPath string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	abs, err := s.absPool(poolPath)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(abs)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s *Store) Delete(ctx context.Context, poolPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	abs, err := s.absPool(poolPath)
	if err != nil {
		return err
	}
	return os.Remove(abs)
}

func (s *Store) ComputeChecksums(ctx context.Context, poolPath string) (model.Checksums, error) {
	rc, err := s.Open(ctx, poolPath)
	if err != nil {
		return model.Checksums{}, err
	}
	defer rc.Close()
	h256 := sha256.New()
	h512 := sha512.New()
	if _, err := io.Copy(io.MultiWriter(h256, h512), rc); err != nil {
		return model.Checksums{}, err
	}
	return model.Checksums{
		SHA256: model.Digest(hex.EncodeToString(h256.Sum(nil))),
		SHA512: model.Digest(hex.EncodeToString(h512.Sum(nil))),
	}, nil
}

func (s *Store) WalkPool(ctx context.Context, fn func(info storage.FileInfo) error) error {
	return filepath.WalkDir(s.poolRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".deb") {
			return nil
		}
		rel, err := filepath.Rel(s.poolRoot, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return fn(storage.FileInfo{
			Path:    filepath.Join("pool", filepath.ToSlash(rel)),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	})
}

func (s *Store) ListPublished(ctx context.Context, prefix string) ([]string, error) {
	infos, err := s.ListPublishedInfo(ctx, prefix)
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(infos))
	for i, fi := range infos {
		paths[i] = fi.Path
	}
	return paths, nil
}

func (s *Store) ListPublishedInfo(ctx context.Context, prefix string) ([]storage.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs := filepath.Join(s.root, filepath.FromSlash(filepath.Clean(prefix)))
	var infos []storage.FileInfo
	err := filepath.WalkDir(abs, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if os.IsNotExist(werr) {
				return nil
			}
			return werr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.root, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		infos = append(infos, storage.FileInfo{
			Path:    filepath.ToSlash(rel),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
		return nil
	})
	return infos, err
}

func (s *Store) WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error {
	abs, err := s.absPublished(relPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".pub-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, abs); err != nil {
		return err
	}
	_ = size
	return nil
}

func (s *Store) DeletePublished(ctx context.Context, relPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	abs, err := s.absPublished(relPath)
	if err != nil {
		return err
	}
	return os.Remove(abs)
}

func (s *Store) OpenPublished(ctx context.Context, relPath string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := s.absPublished(relPath)
	if err != nil {
		return nil, err
	}
	return os.Open(abs)
}

func (s *Store) StatPublished(ctx context.Context, relPath string) (storage.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return storage.FileInfo{}, err
	}
	abs, err := s.absPublished(relPath)
	if err != nil {
		return storage.FileInfo{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return storage.FileInfo{}, err
	}
	return storage.FileInfo{Path: relPath, Size: st.Size(), ModTime: st.ModTime()}, nil
}

func (s *Store) ListSnapshots(ctx context.Context, osName string) ([]storage.SnapshotRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var refs []storage.SnapshotRef
	for _, e := range entries {
		if e.Name() == "current" || e.Name() == "pool" {
			continue
		}
		t, ok := parseSnapshotID(e.Name())
		if !ok {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.root, e.Name(), osName)); err != nil {
			continue
		}
		refs = append(refs, storage.SnapshotRef{
			ID:        e.Name(),
			OS:        osName,
			CreatedAt: t,
		})
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].CreatedAt.Before(refs[j].CreatedAt)
	})
	return refs, nil
}

func (s *Store) ResolveSnapshot(ctx context.Context, osName string, at time.Time) (string, error) {
	refs, err := s.ListSnapshots(ctx, osName)
	if err != nil {
		return "", err
	}
	var chosen string
	for _, ref := range refs {
		if !ref.CreatedAt.After(at) {
			chosen = ref.ID
		}
	}
	if chosen == "" {
		return "", fmt.Errorf("no snapshot for %s at or before %s", osName, at.Format(time.RFC3339))
	}
	return chosen, nil
}

func parseSnapshotID(name string) (time.Time, bool) {
	if t, err := time.Parse("2006-01-02", name); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02T15-04-05", name); err == nil {
		return t, true
	}
	return time.Time{}, false
}

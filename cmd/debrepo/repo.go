package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/publish"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/storage/s3store"
)

// repoFS is what debrepo needs from a repository root, whether it is a
// directory or an S3 prefix: the pool/ and dists/ trees under it, read and
// written by slash-separated path relative to the root.
type repoFS interface {
	publish.FileSink
	// subdirs returns the names of the directories directly under dir, or
	// an error wrapping fs.ErrNotExist when dir has nothing under it.
	subdirs(ctx context.Context, dir string) ([]string, error)
	// walk calls fn for every file under dir, at any depth, whose name
	// ends in suffix, with its path relative to dir, its size and its
	// modification time. A dir that does not exist yields no calls.
	walk(ctx context.Context, dir, suffix string, fn func(rel string, size int64, mtime time.Time)) error
	// open streams a file.
	open(ctx context.Context, rel string) (io.ReadCloser, error)
	// openSeekable returns a file that can be read more than once; for S3
	// that is a temporary local copy, removed on Close.
	openSeekable(ctx context.Context, rel string) (io.ReadSeekCloser, error)
	// rotate moves rel to old, replacing old; a missing rel is not an
	// error.
	rotate(ctx context.Context, rel, old string) error
}

// s3Flags are the connection settings for an s3:// repository root.
type s3Flags struct {
	region    string
	endpoint  string
	pathStyle bool
	noACL     bool
}

// openRepo returns the repository at dir: a directory, or an S3 prefix
// when dir is an s3:// URL.
func openRepo(ctx context.Context, dir string, flags s3Flags) (repoFS, error) {
	if !strings.HasPrefix(strings.ToLower(dir), "s3://") {
		return localRepo{root: dir}, nil
	}
	repo, err := openS3Repo(ctx, dir, flags)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// localRepo is a repository root on the local filesystem.
type localRepo struct{ root string }

func (l localRepo) full(rel string) string {
	return filepath.Join(l.root, filepath.FromSlash(rel))
}

func (l localRepo) subdirs(_ context.Context, dir string) ([]string, error) {
	entries, err := os.ReadDir(l.full(dir))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (l localRepo) walk(_ context.Context, dir, suffix string, fn func(rel string, size int64, mtime time.Time)) error {
	base := l.full(dir)
	if _, err := os.Stat(base); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
		if warnWalkErr(dir, p, err) {
			return nil
		}
		if info == nil || info.IsDir() || !strings.HasSuffix(info.Name(), suffix) {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		fn(filepath.ToSlash(rel), info.Size(), info.ModTime())
		return nil
	})
}

func (l localRepo) open(_ context.Context, rel string) (io.ReadCloser, error) {
	return os.Open(l.full(rel))
}

func (l localRepo) openSeekable(_ context.Context, rel string) (io.ReadSeekCloser, error) {
	return os.Open(l.full(rel))
}

func (l localRepo) rotate(_ context.Context, rel, old string) error {
	err := os.Rename(l.full(rel), l.full(old))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// WriteFile writes relPath through a temporary file and a rename, so a
// reader never sees a partial file.
func (l localRepo) WriteFile(_ context.Context, relPath string, r io.Reader, _ int64) error {
	full := l.full(relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, full)
}

// s3Repo is a repository root under a bucket prefix. One listing of the
// whole prefix, taken when the repository is opened, answers every
// directory and file question; S3 has no directories, so a "directory" is
// any object key below it, including a zero-byte marker key ending in "/".
type s3Repo struct {
	store *s3store.Store
	files []storage.FileInfo
}

// parseS3Dir splits s3://[key:secret@]bucket[/prefix] into its parts. The
// credentials are taken literally. No error message includes the URL,
// which may hold the secret.
func parseS3Dir(dir string) (bucket, prefix, accessKey, secret string, err error) {
	u, err := url.Parse(dir)
	if err != nil {
		return "", "", "", "", errors.New("-dir: s3 url does not parse")
	}
	if u.Scheme != "s3" || u.Host == "" || strings.Contains(u.Host, ":") {
		return "", "", "", "", errors.New("-dir: an s3 url is s3://bucket/prefix with a bare bucket name; a port belongs in -s3-endpoint")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", "", errors.New("-dir: s3 url must not contain a query or fragment")
	}
	if strings.Contains(u.Path, "@") {
		return "", "", "", "", errors.New("-dir: s3 url has an \"@\" after the credentials; write a \"/\" inside the secret as %2F")
	}
	if u.User != nil {
		accessKey = u.User.Username()
		secret, _ = u.User.Password()
		if accessKey == "" || secret == "" {
			return "", "", "", "", errors.New("-dir: s3 credentials need both the access key id and the secret")
		}
	}
	return u.Host, strings.Trim(u.Path, "/"), accessKey, secret, nil
}

func openS3Repo(ctx context.Context, dir string, flags s3Flags) (*s3Repo, error) {
	bucket, prefix, accessKey, secret, err := parseS3Dir(dir)
	if err != nil {
		return nil, err
	}
	region := flags.region
	if region == "" {
		// The SDK's own resolution: AWS_REGION, AWS_DEFAULT_REGION, then
		// the region of the shared config's profile.
		if awsCfg, err := awsconfig.LoadDefaultConfig(ctx); err == nil {
			region = awsCfg.Region
		}
	}
	if region == "" {
		return nil, errors.New("-s3-region, AWS_REGION or a region in the shared config is required for an s3:// repository")
	}
	var opts []s3store.Option
	if accessKey != "" {
		opts = append(opts, s3store.WithStaticCredentials(accessKey, secret))
	}
	store, err := s3store.New(config.S3Config{
		Bucket:         bucket,
		Prefix:         prefix,
		Region:         region,
		Endpoint:       flags.endpoint,
		ForcePathStyle: flags.pathStyle,
		DisableACL:     flags.noACL,
	}, opts...)
	if err != nil {
		return nil, err
	}
	listed, err := store.ListPublishedInfo(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list s3://%s/%s: %w", bucket, prefix, err)
	}
	// The listing is used as given for directory and file names, while
	// reads and writes go through storage.CleanRelPath, which collapses
	// "//" and dot segments. A key the two would disagree on (one that
	// names a file this run could not read back, or a ".." codename that
	// would put Release files at the prefix root) is left out.
	files := listed[:0]
	for _, f := range listed {
		p := strings.TrimSuffix(f.Path, "/")
		if clean, err := storage.CleanRelPath(p); err != nil || clean != p {
			slog.Warn("ignoring object with a path that does not clean to itself", "key", f.Path)
			continue
		}
		files = append(files, f)
	}
	return &s3Repo{store: store, files: files}, nil
}

func (s *s3Repo) subdirs(_ context.Context, dir string) ([]string, error) {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	seen := map[string]bool{}
	found := false
	for _, f := range s.files {
		rest, ok := strings.CutPrefix(f.Path, prefix)
		if !ok {
			continue
		}
		found = true
		if name, _, ok := strings.Cut(rest, "/"); ok && name != "" {
			seen[name] = true
		}
	}
	if !found {
		return nil, &fs.PathError{Op: "list", Path: dir, Err: fs.ErrNotExist}
	}
	return sortedKeys(seen), nil
}

func (s *s3Repo) walk(_ context.Context, dir, suffix string, fn func(rel string, size int64, mtime time.Time)) error {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for _, f := range s.files {
		if rel, ok := strings.CutPrefix(f.Path, prefix); ok && strings.HasSuffix(rel, suffix) {
			fn(rel, f.Size, f.ModTime)
		}
	}
	return nil
}

func (s *s3Repo) open(ctx context.Context, rel string) (io.ReadCloser, error) {
	return s.store.OpenPublished(ctx, rel)
}

// openSeekable downloads the object once into a temporary file, which is
// removed when the returned file is closed.
func (s *s3Repo) openSeekable(ctx context.Context, rel string) (io.ReadSeekCloser, error) {
	rc, err := s.store.OpenPublished(ctx, rel)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp("", "debrepo-*")
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("download %s: %w", rel, err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	return &tempFile{File: tmp}, nil
}

type tempFile struct{ *os.File }

func (t *tempFile) Close() error {
	err := t.File.Close()
	os.Remove(t.Name())
	return err
}

// rotate copies rel to old; S3 has no rename.
func (s *s3Repo) rotate(ctx context.Context, rel, old string) error {
	rc, err := s.store.OpenPublished(ctx, rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return err
	}
	return s.store.WriteFile(ctx, old, bytes.NewReader(data), int64(len(data)))
}

func (s *s3Repo) WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error {
	return s.store.WriteFile(ctx, relPath, r, size)
}

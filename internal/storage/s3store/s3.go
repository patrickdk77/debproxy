package s3store

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
)

// Store implements S3-backed pool and published trees.
type Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// New returns an S3 storage backend.
func New(cfg config.S3Config) (*Store, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3.bucket is required")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("s3.region is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	return &Store{
		client: s3.NewFromConfig(awsCfg),
		bucket: cfg.Bucket,
		prefix: strings.Trim(cfg.Prefix, "/"),
	}, nil
}

func (s *Store) Ping(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	return err
}

func (s *Store) PutFile(ctx context.Context, poolPath string, r io.Reader, size int64) error {
	key, err := s.s3Key(poolPath)
	if err != nil {
		return err
	}
	acl, cacheControl, contentType := s3PutAttrs(poolPath)
	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        r,
		IfNoneMatch: aws.String("*"),
		ContentType: aws.String(contentType),
	}
	if size >= 0 {
		input.ContentLength = aws.Int64(size)
	}
	if acl != "" {
		input.ACL = acl
	}
	if cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}
	_, err = s.client.PutObject(ctx, input)
	if err != nil {
		if isPreconditionFailed(err) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Store) Open(ctx context.Context, poolPath string) (io.ReadCloser, error) {
	key, err := s.s3Key(poolPath)
	if err != nil {
		return nil, err
	}
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	return output.Body, nil
}

func (s *Store) Stat(ctx context.Context, poolPath string) (storage.FileInfo, error) {
	key, err := s.s3Key(poolPath)
	if err != nil {
		return storage.FileInfo{}, err
	}
	meta, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return storage.FileInfo{}, err
	}
	return storage.FileInfo{Path: poolPath, Size: aws.ToInt64(meta.ContentLength), ModTime: aws.ToTime(meta.LastModified)}, nil
}

func (s *Store) Exists(ctx context.Context, poolPath string) (bool, error) {
	key, err := s.s3Key(poolPath)
	if err != nil {
		return false, err
	}
	_, err = s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, err
}

func (s *Store) Delete(ctx context.Context, poolPath string) error {
	key, err := s.s3Key(poolPath)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return err
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
		SHA256: model.Digest(fmt.Sprintf("%x", h256.Sum(nil))),
		SHA512: model.Digest(fmt.Sprintf("%x", h512.Sum(nil))),
	}, nil
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
	s3Prefix, err := s.s3Key(prefix)
	if err != nil {
		return nil, err
	}
	if s3Prefix != "" && !strings.HasSuffix(s3Prefix, "/") {
		s3Prefix += "/"
	}
	rootPrefix := ""
	if s.prefix != "" {
		rootPrefix = s.prefix + "/"
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s3Prefix),
	})
	var infos []storage.FileInfo
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			rel := strings.TrimPrefix(aws.ToString(obj.Key), rootPrefix)
			if rel != "" {
				infos = append(infos, storage.FileInfo{
					Path:    rel,
					Size:    aws.ToInt64(obj.Size),
					ModTime: aws.ToTime(obj.LastModified),
				})
			}
		}
	}
	return infos, nil
}

// CleanupTempFiles is a no-op: PutFile issues a single atomic PutObject S3
// API call with no temp key of our own to leak if it's interrupted -- an
// in-progress or aborted upload simply never creates the object, nothing for
// us to find and remove.
func (s *Store) CleanupTempFiles(ctx context.Context, olderThan time.Time) (int, error) {
	return 0, nil
}

func (s *Store) WalkPool(ctx context.Context, fn func(info storage.FileInfo) error) error {
	prefix, err := s.s3Key("pool/")
	if err != nil {
		return err
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(prefix)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			key := aws.ToString(obj.Key)
			if !strings.HasSuffix(strings.ToLower(key), ".deb") {
				continue
			}
			rel := strings.TrimPrefix(key, prefix)
			if strings.HasPrefix(rel, "/") {
				rel = strings.TrimPrefix(rel, "/")
			}
			if rel == "" {
				continue
			}
			info := storage.FileInfo{
				Path:    path.Join("pool", rel),
				Size:    aws.ToInt64(obj.Size),
				ModTime: aws.ToTime(obj.LastModified),
			}
			if err := fn(info); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error {
	key, err := s.s3Key(relPath)
	if err != nil {
		return err
	}
	acl, cacheControl, contentType := s3PutAttrs(relPath)
	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        r,
		ContentType: aws.String(contentType),
	}
	if size >= 0 {
		input.ContentLength = aws.Int64(size)
	}
	if acl != "" {
		input.ACL = acl
	}
	if cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}
	_, err = s.client.PutObject(ctx, input)
	return err
}

func (s *Store) DeletePublished(ctx context.Context, relPath string) error {
	key, err := s.s3Key(relPath)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return err
}

func (s *Store) OpenPublished(ctx context.Context, relPath string) (io.ReadCloser, error) {
	return s.Open(ctx, relPath)
}

func (s *Store) StatPublished(ctx context.Context, relPath string) (storage.FileInfo, error) {
	return s.Stat(ctx, relPath)
}

func (s *Store) ListSnapshots(ctx context.Context, osName string) ([]storage.SnapshotRef, error) {
	rootPrefix, err := s.s3Key("")
	if err != nil {
		return nil, err
	}
	if rootPrefix != "" && !strings.HasSuffix(rootPrefix, "/") {
		rootPrefix += "/"
	}
	input := &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(rootPrefix), Delimiter: aws.String("/")}
	refs := make([]storage.SnapshotRef, 0)
	for paginator := s3.NewListObjectsV2Paginator(s.client, input); paginator.HasMorePages(); {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cp := range page.CommonPrefixes {
			if cp.Prefix == nil {
				continue
			}
			name := strings.TrimPrefix(aws.ToString(cp.Prefix), rootPrefix)
			name = strings.TrimSuffix(name, "/")
			if name == "pool" || name == "current" || name == "keys" || name == "" {
				continue
			}
			t, ok := parseSnapshotID(name)
			if !ok {
				continue
			}
			if exists, err := s.snapshotHasOS(ctx, name, osName); err != nil {
				return nil, err
			} else if !exists {
				continue
			}
			refs = append(refs, storage.SnapshotRef{ID: name, OS: osName, CreatedAt: t})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].CreatedAt.Before(refs[j].CreatedAt) })
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

// s3PutAttrs returns the ACL, Cache-Control, and Content-Type for a PUT based
// on the logical path within the storage root:
//   - metadata/**        -> private (no ACL), no cache header
//   - current/**         -> public-read, max-age=720 (refreshed on each snapshot)
//   - keys/debproxy.*    -> public-read, max-age=86400 (rotates on key change)
//   - everything else    -> public-read, max-age=31536000, immutable
func s3PutAttrs(relPath string) (acl types.ObjectCannedACL, cacheControl, contentType string) {
	contentType = s3ContentType(relPath)
	if strings.HasPrefix(relPath, "metadata/") {
		return
	}
	acl = types.ObjectCannedACLPublicRead
	switch {
	case strings.HasPrefix(relPath, "current/"):
		cacheControl = "public, max-age=720"
	case strings.HasPrefix(relPath, "keys/") && strings.HasPrefix(path.Base(relPath), "debproxy."):
		cacheControl = "public, max-age=86400"
	default:
		cacheControl = "public, max-age=31536000, immutable"
	}
	return
}

func s3ContentType(relPath string) string {
	name := path.Base(relPath)
	switch path.Ext(name) {
	case ".deb":
		return "application/vnd.debian.binary-package"
	case ".asc":
		return "text/plain; charset=utf-8"
	case ".gz":
		return "application/gzip"
	case ".zst":
		return "application/zstd"
	case ".gpg":
		if name == "Release.gpg" {
			return "application/pgp-signature"
		}
		return "application/pgp-keys"
	default:
		return "text/plain; charset=utf-8"
	}
}

func (s *Store) s3Key(key string) (string, error) {
	clean, err := storage.CleanRelPath(key)
	if err != nil {
		return "", err
	}
	if s.prefix == "" {
		return clean, nil
	}
	if clean == "" {
		return s.prefix, nil
	}
	return path.Join(s.prefix, clean), nil
}

func (s *Store) snapshotHasOS(ctx context.Context, snapshotID, osName string) (bool, error) {
	prefix, err := s.s3Key(path.Join(snapshotID, osName, ""))
	if err != nil {
		return false, err
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	input := &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(prefix), MaxKeys: aws.Int32(1)}
	page, err := s.client.ListObjectsV2(ctx, input)
	if err != nil {
		return false, err
	}
	return len(page.Contents) > 0, nil
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

func isNotFound(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NotFound" || apiErr.ErrorCode() == "NoSuchKey"
	}
	return false
}

func isPreconditionFailed(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "PreconditionFailed"
}

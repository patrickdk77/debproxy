package s3store

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// s3API is the subset of the S3 client the Store uses. Depending on a narrow
// interface (which *s3.Client satisfies) rather than the concrete client is
// what makes every Store method unit-testable with a fake -- the concrete
// client cannot be faked, which is why the backend's error handling previously
// had no test coverage at all. It also satisfies s3.ListObjectsV2APIClient, so
// the paginators accept it directly.
type s3API interface {
	HeadBucket(ctx context.Context, in *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// Store implements S3-backed pool and published trees.
type Store struct {
	client s3API
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

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		// Custom endpoint + path-style support for S3-compatible providers
		// (R2/MinIO/B2/Spaces/Ceph). Both are no-ops when unset, preserving
		// standard AWS behavior.
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		if cfg.ForcePathStyle {
			o.UsePathStyle = true
		}
	})

	return &Store{
		client: client,
		bucket: cfg.Bucket,
		prefix: strings.Trim(cfg.Prefix, "/"),
	}, nil
}

func (s *Store) Ping(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	return wrapS3("headbucket", s.bucket, err)
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
		// IfNoneMatch=* makes this write-once: a PreconditionFailed means the
		// object already exists, which is success for our purposes.
		if isPreconditionFailed(err) {
			return nil
		}
		return wrapS3("put", poolPath, err)
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
		return nil, wrapObjectRead("open", poolPath, err)
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
		return storage.FileInfo{}, wrapObjectRead("stat", poolPath, err)
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
	// A missing object (404, or 403 without ListBucket) means "does not exist";
	// a credential failure or other error is surfaced.
	if isMissingOnRead(err) {
		return false, nil
	}
	return false, wrapS3("stat", poolPath, err)
}

func (s *Store) Delete(ctx context.Context, poolPath string) error {
	key, err := s.s3Key(poolPath)
	if err != nil {
		return err
	}
	// S3 DeleteObject is idempotent: deleting an absent key returns success, so
	// there is no not-found case to handle here.
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return wrapS3("delete", poolPath, err)
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
			return nil, wrapS3("list", prefix, err)
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
			return wrapS3("list", "pool/", err)
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
	return wrapS3("put", relPath, err)
}

func (s *Store) DeletePublished(ctx context.Context, relPath string) error {
	key, err := s.s3Key(relPath)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return wrapS3("delete", relPath, err)
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
			return nil, wrapS3("list", rootPrefix, err)
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
		return false, wrapS3("list", prefix, err)
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

// s3ErrorCode returns the S3/smithy API error code, or "" if err is not an
// API error (network error, context cancellation, etc.).
func s3ErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// isNotFound reports a definitive "object/bucket does not exist" response.
func isNotFound(err error) bool {
	switch s3ErrorCode(err) {
	case "NotFound", "NoSuchKey", "NoSuchBucket":
		return true
	}
	return false
}

// isForbidden reports a 403 caused by object/prefix-scoped permissions. On a
// bucket whose IAM policy omits s3:ListBucket, S3 answers a GET/HEAD of a
// MISSING key with 403 AccessDenied instead of 404 -- so for object reads this
// is indistinguishable from, and treated as, not-found (see isMissingOnRead).
func isForbidden(err error) bool {
	switch s3ErrorCode(err) {
	case "AccessDenied", "Forbidden":
		return true
	}
	return false
}

// isCredentialFailure reports a total-auth failure (bad/expired/mismatched
// credentials or a disabled account). These are NOT per-key permission answers
// and must never be masked as not-found: every request would fail, so surfacing
// them loudly is the only way to diagnose the misconfiguration.
func isCredentialFailure(err error) bool {
	switch s3ErrorCode(err) {
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken",
		"InvalidToken", "TokenRefreshRequired", "AllAccessDisabled", "AccountProblem":
		return true
	}
	return false
}

// isMissingOnRead reports whether a GET/HEAD object error should be treated as
// "object not present". It covers both a genuine 404 and the 403 that S3
// returns for a missing key when the caller lacks s3:ListBucket -- but never a
// credential failure, which would otherwise make every read look like a miss.
func isMissingOnRead(err error) bool {
	if isCredentialFailure(err) {
		return false
	}
	return isNotFound(err) || isForbidden(err)
}

func isPreconditionFailed(err error) bool {
	return s3ErrorCode(err) == "PreconditionFailed"
}

// wrapObjectRead normalizes a GetObject/HeadObject error: a missing object
// (404, or 403 when ListBucket is absent) becomes an fs.PathError wrapping
// fs.ErrNotExist so os.IsNotExist / errors.Is(err, fs.ErrNotExist) behave
// exactly as with the filesystem backend. Everything else is wrapped with
// context via wrapS3 (credential failures included).
func wrapObjectRead(op, key string, err error) error {
	if err == nil {
		return nil
	}
	if isMissingOnRead(err) {
		return &fs.PathError{Op: op, Path: key, Err: fs.ErrNotExist}
	}
	return wrapS3(op, key, err)
}

// wrapS3 normalizes a non-object-read S3 error (writes, deletes, lists, bucket
// ops): definitive not-found becomes fs.ErrNotExist; a 403/credential failure
// is annotated with storage.ErrAccessDenied so a permissions misconfiguration
// is diagnosable (and matchable with errors.Is); anything else is annotated
// with the operation and key. The original error is preserved in the chain
// (%w) so smithy code/precondition inspection upstream keeps working. Unlike
// object reads, a 403 here is a real denial (you cannot list/write), not a
// disguised not-found.
func wrapS3(op, key string, err error) error {
	if err == nil {
		return nil
	}
	if isNotFound(err) {
		return &fs.PathError{Op: op, Path: key, Err: fs.ErrNotExist}
	}
	if isForbidden(err) || isCredentialFailure(err) {
		return fmt.Errorf("s3 %s %q: %w: %w", op, key, storage.ErrAccessDenied, err)
	}
	return fmt.Errorf("s3 %s %q: %w", op, key, err)
}

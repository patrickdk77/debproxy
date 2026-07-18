package s3store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/debproxy/debproxy/internal/storage"
)

// fakeS3 is a programmable s3API used to drive the real Store methods so their
// error mapping and success paths are exercised without a live S3 endpoint.
type fakeS3 struct {
	headObject   func() (*s3.HeadObjectOutput, error)
	getObject    func() (*s3.GetObjectOutput, error)
	putObject    func(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	deleteObject func() (*s3.DeleteObjectOutput, error)
	headBucket   func() (*s3.HeadBucketOutput, error)
	listObjects  func() (*s3.ListObjectsV2Output, error)
}

func (f *fakeS3) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return f.headObject()
}
func (f *fakeS3) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return f.getObject()
}
func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return f.putObject(in)
}
func (f *fakeS3) DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	return f.deleteObject()
}
func (f *fakeS3) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return f.headBucket()
}
func (f *fakeS3) ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return f.listObjects()
}

func storeWith(f *fakeS3) *Store { return &Store{client: f, bucket: "b"} }

func headErr(code string) func() (*s3.HeadObjectOutput, error) {
	return func() (*s3.HeadObjectOutput, error) { return nil, apiErr(code) }
}

// TestStat_ErrorMapping is the test that would have caught the original
// production bug: before the fix, Stat returned the raw smithy error and
// os.IsNotExist(err) was false, so the caller treated a missing key as fatal.
func TestStat_ErrorMapping(t *testing.T) {
	ctx := context.Background()

	// 404 and (ListBucket-less) 403 must both look like not-exist.
	for _, code := range []string{"NotFound", "NoSuchKey", "AccessDenied", "Forbidden"} {
		s := storeWith(&fakeS3{headObject: headErr(code)})
		_, err := s.Stat(ctx, "pool/x.deb")
		if !os.IsNotExist(err) {
			t.Errorf("Stat(HeadObject=%s): os.IsNotExist = false, want true (err=%v)", code, err)
		}
	}

	// A credential failure must NOT masquerade as not-exist.
	s := storeWith(&fakeS3{headObject: headErr("InvalidAccessKeyId")})
	if _, err := s.Stat(ctx, "pool/x.deb"); err == nil || os.IsNotExist(err) || !errors.Is(err, storage.ErrAccessDenied) {
		t.Errorf("Stat(credential failure) = %v, want access-denied (not not-exist)", err)
	}

	// Success returns the file info.
	ok := storeWith(&fakeS3{headObject: func() (*s3.HeadObjectOutput, error) {
		return &s3.HeadObjectOutput{ContentLength: aws.Int64(42), LastModified: aws.Time(time.Unix(1000, 0))}, nil
	}})
	info, err := ok.Stat(ctx, "pool/x.deb")
	if err != nil || info.Size != 42 || info.Path != "pool/x.deb" {
		t.Errorf("Stat(success) = %+v, %v", info, err)
	}
}

func TestOpen_ErrorMapping(t *testing.T) {
	ctx := context.Background()

	s := storeWith(&fakeS3{getObject: func() (*s3.GetObjectOutput, error) { return nil, apiErr("NoSuchKey") }})
	if _, err := s.Open(ctx, "pool/x.deb"); !os.IsNotExist(err) {
		t.Errorf("Open(NoSuchKey): os.IsNotExist = false, want true (err=%v)", err)
	}

	body := io.NopCloser(strings.NewReader("hello"))
	ok := storeWith(&fakeS3{getObject: func() (*s3.GetObjectOutput, error) { return &s3.GetObjectOutput{Body: body}, nil }})
	rc, err := ok.Open(ctx, "pool/x.deb")
	if err != nil {
		t.Fatalf("Open(success): %v", err)
	}
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Errorf("Open body = %q, want hello", got)
	}
}

func TestExists_ErrorMapping(t *testing.T) {
	ctx := context.Background()

	miss := storeWith(&fakeS3{headObject: headErr("NotFound")})
	if ok, err := miss.Exists(ctx, "k"); ok || err != nil {
		t.Errorf("Exists(NotFound) = %v, %v; want false, nil", ok, err)
	}
	forbidden := storeWith(&fakeS3{headObject: headErr("AccessDenied")})
	if ok, err := forbidden.Exists(ctx, "k"); ok || err != nil {
		t.Errorf("Exists(403 w/o ListBucket) = %v, %v; want false, nil", ok, err)
	}
	present := storeWith(&fakeS3{headObject: func() (*s3.HeadObjectOutput, error) { return &s3.HeadObjectOutput{}, nil }})
	if ok, err := present.Exists(ctx, "k"); !ok || err != nil {
		t.Errorf("Exists(present) = %v, %v; want true, nil", ok, err)
	}
	cred := storeWith(&fakeS3{headObject: headErr("SignatureDoesNotMatch")})
	if ok, err := cred.Exists(ctx, "k"); ok || err == nil {
		t.Errorf("Exists(credential failure) = %v, %v; want false, error", ok, err)
	}
}

func TestPutFile_ErrorMapping(t *testing.T) {
	ctx := context.Background()

	// Write-once: a PreconditionFailed (object already exists) is success.
	exists := storeWith(&fakeS3{putObject: func(*s3.PutObjectInput) (*s3.PutObjectOutput, error) { return nil, apiErr("PreconditionFailed") }})
	if err := exists.PutFile(ctx, "pool/x.deb", strings.NewReader("x"), 1); err != nil {
		t.Errorf("PutFile(PreconditionFailed) = %v, want nil (already exists)", err)
	}

	denied := storeWith(&fakeS3{putObject: func(*s3.PutObjectInput) (*s3.PutObjectOutput, error) { return nil, apiErr("AccessDenied") }})
	if err := denied.PutFile(ctx, "pool/x.deb", strings.NewReader("x"), 1); !errors.Is(err, storage.ErrAccessDenied) {
		t.Errorf("PutFile(AccessDenied) = %v, want storage.ErrAccessDenied", err)
	}

	ok := storeWith(&fakeS3{putObject: func(*s3.PutObjectInput) (*s3.PutObjectOutput, error) { return &s3.PutObjectOutput{}, nil }})
	if err := ok.PutFile(ctx, "pool/x.deb", strings.NewReader("x"), 1); err != nil {
		t.Errorf("PutFile(success) = %v", err)
	}
}

// TestPutFile_ACLFallback verifies the bucket-owner-enforced recovery: the
// first upload attempts an ACL, the bucket rejects it, and the store retries
// the same upload without an ACL, then never sends an ACL again.
func TestPutFile_ACLFallback(t *testing.T) {
	ctx := context.Background()

	var acls []string // ACL value seen on each PutObject attempt
	firstAttempt := true
	fake := &fakeS3{putObject: func(in *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		acls = append(acls, string(in.ACL))
		if firstAttempt {
			firstAttempt = false
			return nil, apiErr("AccessControlListNotSupported")
		}
		return &s3.PutObjectOutput{}, nil
	}}
	s := storeWith(fake)

	// A seekable body so the retry can rewind (bytes.Reader is an io.Seeker).
	if err := s.PutFile(ctx, "pool/x.deb", bytes.NewReader([]byte("data")), 4); err != nil {
		t.Fatalf("PutFile with ACL fallback = %v, want success", err)
	}
	if len(acls) != 2 {
		t.Fatalf("PutObject attempts = %d, want 2 (with-ACL then retry-without)", len(acls))
	}
	if acls[0] == "" {
		t.Error("first attempt sent no ACL, want the public-read ACL")
	}
	if acls[1] != "" {
		t.Errorf("retry attempt sent ACL %q, want none", acls[1])
	}

	// A subsequent upload must skip the ACL entirely -- no wasted round trip.
	if err := s.PutFile(ctx, "pool/y.deb", bytes.NewReader([]byte("more")), 4); err != nil {
		t.Fatalf("second PutFile = %v", err)
	}
	if len(acls) != 3 || acls[2] != "" {
		t.Errorf("after ACL disabled, attempts=%d last ACL=%q; want 1 more attempt with no ACL", len(acls), acls[len(acls)-1])
	}
}

// TestPutFile_ACLFallbackNonSeekable documents that a non-seekable body cannot
// be retried: the recovery needs to rewind, so such a body yields a clear error
// rather than a silent truncated re-upload.
func TestPutFile_ACLFallbackNonSeekable(t *testing.T) {
	ctx := context.Background()
	fake := &fakeS3{putObject: func(*s3.PutObjectInput) (*s3.PutObjectOutput, error) {
		return nil, apiErr("AccessControlListNotSupported")
	}}
	s := storeWith(fake)
	// A bare Reader (no Seek) wrapping a reader.
	body := struct{ io.Reader }{strings.NewReader("data")}
	if err := s.PutFile(ctx, "pool/x.deb", body, 4); err == nil {
		t.Error("PutFile(non-seekable body, ACL rejected) = nil, want a clear retry error")
	}
}

func TestStatPublished_DelegatesMapping(t *testing.T) {
	ctx := context.Background()
	s := storeWith(&fakeS3{headObject: headErr("NotFound")})
	if _, err := s.StatPublished(ctx, "keys/FP.asc"); !os.IsNotExist(err) {
		t.Errorf("StatPublished(NotFound): os.IsNotExist = false, want true (err=%v)", err)
	}
	if !errors.Is(func() error { _, e := s.StatPublished(ctx, "keys/FP.asc"); return e }(), fs.ErrNotExist) {
		t.Error("StatPublished: errors.Is(fs.ErrNotExist) = false, want true")
	}
}

func TestListPublishedInfo_AccessDenied(t *testing.T) {
	ctx := context.Background()
	s := storeWith(&fakeS3{listObjects: func() (*s3.ListObjectsV2Output, error) { return nil, apiErr("AccessDenied") }})
	if _, err := s.ListPublishedInfo(ctx, "dists/"); !errors.Is(err, storage.ErrAccessDenied) {
		t.Errorf("ListPublishedInfo(AccessDenied) = %v, want storage.ErrAccessDenied", err)
	}
}

func TestPing_ErrorMapping(t *testing.T) {
	ctx := context.Background()
	denied := storeWith(&fakeS3{headBucket: func() (*s3.HeadBucketOutput, error) { return nil, apiErr("AccessDenied") }})
	if err := denied.Ping(ctx); !errors.Is(err, storage.ErrAccessDenied) {
		t.Errorf("Ping(AccessDenied) = %v, want storage.ErrAccessDenied", err)
	}
	ok := storeWith(&fakeS3{headBucket: func() (*s3.HeadBucketOutput, error) { return &s3.HeadBucketOutput{}, nil }})
	if err := ok.Ping(ctx); err != nil {
		t.Errorf("Ping(success) = %v", err)
	}
}

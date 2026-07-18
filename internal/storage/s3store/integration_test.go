package s3store_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/storage/s3store"
	"github.com/debproxy/debproxy/internal/testsupport"
)

// TestS3Integration_RealServer exercises the real Store methods against a real
// S3 server (MinIO) via the actual AWS SDK, so error codes and endpoint/
// path-style wiring are validated against a genuine S3 implementation rather
// than assumed. Skips when Docker is unavailable.
func TestS3Integration_RealServer(t *testing.T) {
	addr, stop, err := testsupport.StartMinIO()
	if err != nil {
		t.Skipf("MinIO unavailable (Docker required): %v", err)
	}
	defer stop()

	// Credentials/region for the whole AWS chain used by both the admin client
	// (bucket setup) and the Store under test.
	t.Setenv("AWS_ACCESS_KEY_ID", testsupport.MinIOAccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", testsupport.MinIOSecretKey)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	ctx := context.Background()
	endpoint := "http://" + addr
	const bucket = "debproxy-it"

	// Create the bucket with a raw client (the Store has no CreateBucket).
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	admin := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	if _, err := admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	// The Store under test, pointed at MinIO through the new endpoint/path-style
	// config -- this also proves that wiring works.
	store, err := s3store.New(config.S3Config{
		Bucket:         bucket,
		Region:         "us-east-1",
		Endpoint:       endpoint,
		ForcePathStyle: true,
	})
	if err != nil {
		t.Fatalf("s3store.New: %v", err)
	}

	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// --- not-found behavior against a REAL server (the original bug) ---
	if _, err := store.Stat(ctx, "pool/missing.deb"); !os.IsNotExist(err) {
		t.Errorf("Stat(missing): os.IsNotExist = false, want true (err=%v)", err)
	}
	if _, err := store.Stat(ctx, "pool/missing.deb"); !errors.Is(err, fs.ErrNotExist) {
		t.Error("Stat(missing): errors.Is(fs.ErrNotExist) = false, want true")
	}
	if _, err := store.Open(ctx, "pool/missing.deb"); !os.IsNotExist(err) {
		t.Errorf("Open(missing): os.IsNotExist = false, want true (err=%v)", err)
	}
	if ok, err := store.Exists(ctx, "pool/missing.deb"); ok || err != nil {
		t.Errorf("Exists(missing) = %v, %v; want false, nil", ok, err)
	}

	// --- pool round-trip ---
	const poolPath = "pool/d/debproxy/hello_1.0_amd64.deb"
	payload := []byte("fake .deb contents")
	if err := store.PutFile(ctx, poolPath, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	if ok, err := store.Exists(ctx, poolPath); !ok || err != nil {
		t.Errorf("Exists(present) = %v, %v; want true, nil", ok, err)
	}
	info, err := store.Stat(ctx, poolPath)
	if err != nil || info.Size != int64(len(payload)) {
		t.Errorf("Stat(present) = %+v, %v; want size %d", info, err, len(payload))
	}
	rc, err := store.Open(ctx, poolPath)
	if err != nil {
		t.Fatalf("Open(present): %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Errorf("Open body = %q, want %q", got, payload)
	}

	// --- write-once: a second PutFile of the same key is a no-op success ---
	if err := store.PutFile(ctx, poolPath, strings.NewReader("different"), 9); err != nil {
		t.Errorf("PutFile(existing key) = %v, want nil (write-once)", err)
	}
	rc, _ = store.Open(ctx, poolPath)
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Errorf("write-once violated: body = %q, want original %q", got, payload)
	}

	// --- published tree round-trip + listing ---
	const relPath = "dists/stable/InRelease"
	body := []byte("Origin: debproxy\n")
	if err := store.WriteFile(ctx, relPath, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := store.StatPublished(ctx, relPath); err != nil {
		t.Errorf("StatPublished: %v", err)
	}
	prc, err := store.OpenPublished(ctx, relPath)
	if err != nil {
		t.Fatalf("OpenPublished: %v", err)
	}
	pgot, _ := io.ReadAll(prc)
	prc.Close()
	if !bytes.Equal(pgot, body) {
		t.Errorf("OpenPublished body = %q, want %q", pgot, body)
	}
	infos, err := store.ListPublishedInfo(ctx, "dists/")
	if err != nil {
		t.Fatalf("ListPublishedInfo: %v", err)
	}
	found := false
	for _, fi := range infos {
		if fi.Path == relPath {
			found = true
		}
	}
	if !found {
		t.Errorf("ListPublishedInfo(dists/) = %v, want it to include %s", infos, relPath)
	}

	// --- delete ---
	if err := store.DeletePublished(ctx, relPath); err != nil {
		t.Errorf("DeletePublished: %v", err)
	}
	if ok, _ := store.Exists(ctx, relPath); ok {
		t.Error("Exists after DeletePublished = true, want false")
	}

	// --- ACLs-disabled bucket (Object Ownership = Bucket owner enforced) ---
	// A store's default upload sends a public-read ACL; on such a bucket the
	// upload must still succeed via the automatic no-ACL fallback.
	const enforcedBucket = "debproxy-it-noacl"
	_, err = admin.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:          aws.String(enforcedBucket),
		ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
	})
	if err != nil {
		t.Logf("skip ACL-disabled sub-test: MinIO did not accept BucketOwnerEnforced: %v", err)
		return
	}
	noACL, err := s3store.New(config.S3Config{
		Bucket: enforcedBucket, Region: "us-east-1", Endpoint: endpoint, ForcePathStyle: true,
	})
	if err != nil {
		t.Fatalf("s3store.New(enforced): %v", err)
	}
	if err := noACL.PutFile(ctx, poolPath, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Errorf("PutFile on ACLs-disabled bucket = %v, want success (no-ACL fallback)", err)
	}
	rc, err = noACL.Open(ctx, poolPath)
	if err != nil {
		t.Fatalf("Open on ACLs-disabled bucket: %v", err)
	}
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Errorf("readback on ACLs-disabled bucket = %q, want %q", got, payload)
	}
}

package s3store

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/debproxy/debproxy/internal/storage"
)

func apiErr(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code + " message"}
}

// TestWrapObjectRead covers GET/HEAD object mapping: a missing object -- 404 or
// the 403 S3 returns when ListBucket is absent -- must look like fs.ErrNotExist,
// while a total-credential failure must NOT be masked as missing.
func TestWrapObjectRead(t *testing.T) {
	missing := []string{"NotFound", "NoSuchKey", "AccessDenied", "Forbidden"}
	for _, code := range missing {
		err := wrapObjectRead("open", "pool/x.deb", apiErr(code))
		if !os.IsNotExist(err) {
			t.Errorf("wrapObjectRead(%s): os.IsNotExist = false, want true", code)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("wrapObjectRead(%s): errors.Is(fs.ErrNotExist) = false, want true", code)
		}
	}

	// Credential failures must surface, never be treated as a missing object.
	for _, code := range []string{"InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "AllAccessDisabled"} {
		err := wrapObjectRead("open", "pool/x.deb", apiErr(code))
		if os.IsNotExist(err) {
			t.Errorf("wrapObjectRead(%s): os.IsNotExist = true, want false (credential failure must not look like a miss)", code)
		}
		if !errors.Is(err, storage.ErrAccessDenied) {
			t.Errorf("wrapObjectRead(%s): errors.Is(ErrAccessDenied) = false, want true", code)
		}
	}

	// A non-API error (e.g. network) is wrapped but is neither not-exist nor access-denied.
	if err := wrapObjectRead("open", "k", errors.New("dial timeout")); err == nil ||
		os.IsNotExist(err) || errors.Is(err, storage.ErrAccessDenied) {
		t.Errorf("wrapObjectRead(network err) = %v, want a plain wrapped error", err)
	}

	if wrapObjectRead("open", "k", nil) != nil {
		t.Error("wrapObjectRead(nil) != nil")
	}
}

// TestWrapS3 covers writes/lists/bucket ops: a 403 here is a real denial, not a
// disguised miss, and a definitive not-found still maps to fs.ErrNotExist.
func TestWrapS3(t *testing.T) {
	if err := wrapS3("list", "pool/", apiErr("AccessDenied")); os.IsNotExist(err) {
		t.Error("wrapS3(AccessDenied): os.IsNotExist = true, want false (a denied list is not a miss)")
	} else if !errors.Is(err, storage.ErrAccessDenied) {
		t.Error("wrapS3(AccessDenied): errors.Is(ErrAccessDenied) = false, want true")
	}

	if err := wrapS3("headbucket", "b", apiErr("NoSuchBucket")); !os.IsNotExist(err) {
		t.Error("wrapS3(NoSuchBucket): os.IsNotExist = false, want true")
	}

	if err := wrapS3("put", "k", apiErr("InvalidAccessKeyId")); !errors.Is(err, storage.ErrAccessDenied) {
		t.Error("wrapS3(InvalidAccessKeyId): errors.Is(ErrAccessDenied) = false, want true")
	}

	if wrapS3("put", "k", nil) != nil {
		t.Error("wrapS3(nil) != nil")
	}

	// Wrapping must preserve the smithy chain so code inspection still works.
	if !isPreconditionFailed(wrapS3("put", "k", apiErr("PreconditionFailed"))) {
		t.Error("isPreconditionFailed through wrapS3 = false, want true (chain must be preserved)")
	}
}

func TestErrorClassifiers(t *testing.T) {
	if !isNotFound(apiErr("NoSuchKey")) || isNotFound(apiErr("AccessDenied")) {
		t.Error("isNotFound classification wrong")
	}
	if !isForbidden(apiErr("AccessDenied")) || isForbidden(apiErr("NotFound")) {
		t.Error("isForbidden classification wrong")
	}
	if !isCredentialFailure(apiErr("SignatureDoesNotMatch")) || isCredentialFailure(apiErr("AccessDenied")) {
		t.Error("isCredentialFailure classification wrong")
	}
	// A credential failure is not a per-key miss even though it is a 403 class.
	if isMissingOnRead(apiErr("InvalidAccessKeyId")) {
		t.Error("isMissingOnRead(credential failure) = true, want false")
	}
	if !isMissingOnRead(apiErr("AccessDenied")) || !isMissingOnRead(apiErr("NoSuchKey")) {
		t.Error("isMissingOnRead(403/404) = false, want true")
	}
}

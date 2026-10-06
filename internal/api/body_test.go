package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeBodyRejectsOversizedBody is the regression test for the
// unbounded read: a body past the cap must fail to decode rather than
// be buffered in full.
func TestDecodeBodyRejectsOversizedBody(t *testing.T) {
	// Valid JSON that is simply too large: a single long string field.
	payload := `{"force": "` + strings.Repeat("x", maxAPIBodyBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot",
		bytes.NewReader([]byte(payload)))
	rec := httptest.NewRecorder()

	var v struct {
		Force string `json:"force"`
	}
	err := decodeBody(rec, req, &v)
	if err == nil {
		t.Fatal("oversized body decoded without error")
	}
	var mbe *http.MaxBytesError
	if !errors.As(err, &mbe) {
		t.Errorf("err = %v, want *http.MaxBytesError", err)
	}
}

func TestDecodeBodyAcceptsBodyUnderCap(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot",
		strings.NewReader(`{"force": true}`))
	rec := httptest.NewRecorder()

	var v struct {
		Force bool `json:"force"`
	}
	if err := decodeBody(rec, req, &v); err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if !v.Force {
		t.Error("field not decoded")
	}
}

// TestDecodeBodyEmptyIsNotAnError pins the documented contract: every
// /api/v1 body is optional and an absent one leaves zero values.
func TestDecodeBodyEmptyIsNotAnError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	rec := httptest.NewRecorder()
	var v struct {
		Force bool `json:"force"`
	}
	if err := decodeBody(rec, req, &v); err != nil {
		t.Fatalf("empty body returned error: %v", err)
	}
	if v.Force {
		t.Error("zero value expected for absent body")
	}
}

func TestDecodeBodyExactlyAtCapIsAccepted(t *testing.T) {
	// Build a body whose total length is exactly the cap.
	prefix := `{"force": "`
	suffix := `"}`
	fill := maxAPIBodyBytes - len(prefix) - len(suffix)
	payload := prefix + strings.Repeat("x", fill) + suffix
	if len(payload) != maxAPIBodyBytes {
		t.Fatalf("test setup: payload is %d, want %d", len(payload), maxAPIBodyBytes)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot",
		strings.NewReader(payload))
	rec := httptest.NewRecorder()
	var v struct {
		Force string `json:"force"`
	}
	if err := decodeBody(rec, req, &v); err != nil {
		t.Fatalf("body exactly at cap rejected: %v", err)
	}
}

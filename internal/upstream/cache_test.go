package upstream

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIndexCacheHitAndMiss(t *testing.T) {
	c := NewIndexCache()
	const url = "http://example.com/InRelease"

	_, ok := c.get(url)
	if ok {
		t.Fatal("expected miss on empty cache")
	}

	entry := &indexCacheEntry{expires: time.Now().Add(time.Hour)}
	c.store(url, entry)

	got, ok := c.get(url)
	if !ok {
		t.Fatal("expected hit after store")
	}
	if got != entry {
		t.Fatal("got different entry than stored")
	}
}

func TestIndexCacheDifferentURLs(t *testing.T) {
	c := NewIndexCache()
	e1 := &indexCacheEntry{etag: "a"}
	e2 := &indexCacheEntry{etag: "b"}
	c.store("http://a/InRelease", e1)
	c.store("http://b/InRelease", e2)

	g1, _ := c.get("http://a/InRelease")
	g2, _ := c.get("http://b/InRelease")
	if g1.etag != "a" || g2.etag != "b" {
		t.Fatalf("wrong entries: g1.etag=%s g2.etag=%s", g1.etag, g2.etag)
	}
}

func TestParseExpiryMaxAge(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Cache-Control", "max-age=600")
	rec.WriteHeader(http.StatusOK)
	resp := rec.Result()

	exp := parseExpiry(resp)
	want := time.Now().Add(600 * time.Second)
	if exp.Before(want.Add(-5*time.Second)) || exp.After(want.Add(5*time.Second)) {
		t.Fatalf("parseExpiry max-age: got %v, want ~%v", exp, want)
	}
}

func TestParseExpiryNoCache(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Cache-Control", "no-cache")
	rec.WriteHeader(http.StatusOK)
	resp := rec.Result()

	exp := parseExpiry(resp)
	if !exp.IsZero() {
		t.Fatalf("expected zero expiry for no-cache, got %v", exp)
	}
}

func TestParseExpiryFallback(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	resp := rec.Result()

	exp := parseExpiry(resp)
	want := time.Now().Add(5 * time.Minute)
	if exp.Before(want.Add(-5*time.Second)) || exp.After(want.Add(5*time.Second)) {
		t.Fatalf("parseExpiry fallback: got %v, want ~%v", exp, want)
	}
}

func TestParseExpiryExpiresHeader(t *testing.T) {
	future := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	rec := httptest.NewRecorder()
	rec.Header().Set("Expires", future.UTC().Format(http.TimeFormat))
	rec.WriteHeader(http.StatusOK)
	resp := rec.Result()

	exp := parseExpiry(resp)
	if exp.Before(future.Add(-2*time.Second)) || exp.After(future.Add(2*time.Second)) {
		t.Fatalf("parseExpiry Expires header: got %v, want ~%v", exp, future)
	}
}

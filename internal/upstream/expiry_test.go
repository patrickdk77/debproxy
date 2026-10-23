package upstream

import (
	"net/http"
	"testing"
	"time"
)

func respWith(h map[string]string) *http.Response {
	r := &http.Response{Header: http.Header{}}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

// TestParseExpirySubtractsAge is the regression test for the Age sign.
// Age is how long the response has already sat in an intermediate cache,
// so the freshness window must start that long before Date. With
// max-age=60 and Age=50 only ten seconds remain; adding Age instead gave
// one hundred and ten.
func TestParseExpirySubtractsAge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := parseExpiry(respWith(map[string]string{
		"Date":          now.Format(http.TimeFormat),
		"Age":           "50",
		"Cache-Control": "max-age=60",
	}))
	remaining := exp.Sub(now)
	if remaining < 5*time.Second || remaining > 15*time.Second {
		t.Fatalf("expiry %v from now, want about 10s (Age subtracted)", remaining)
	}
}

func TestParseExpiryNoAgeUsesFullMaxAge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := parseExpiry(respWith(map[string]string{
		"Date":          now.Format(http.TimeFormat),
		"Cache-Control": "max-age=60",
	}))
	remaining := exp.Sub(now)
	if remaining < 55*time.Second || remaining > 65*time.Second {
		t.Fatalf("expiry %v from now, want about 60s", remaining)
	}
}

// TestParseExpiryAgeBeyondMaxAgeIsAlreadyStale: a response older than its
// own max-age must come out expired, not freshened.
func TestParseExpiryAgeBeyondMaxAgeIsAlreadyStale(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := parseExpiry(respWith(map[string]string{
		"Date":          now.Format(http.TimeFormat),
		"Age":           "120",
		"Cache-Control": "max-age=60",
	}))
	if !exp.Before(now) {
		t.Fatalf("expiry %v is not in the past for Age > max-age", exp)
	}
}

func TestParseExpiryNoCacheReturnsZero(t *testing.T) {
	exp := parseExpiry(respWith(map[string]string{
		"Cache-Control": "no-cache",
	}))
	if !exp.IsZero() {
		t.Fatalf("no-cache produced expiry %v, want zero", exp)
	}
}

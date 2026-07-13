package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/debproxy/debproxy/internal/auth"
	"github.com/debproxy/debproxy/internal/config"
)

func mustBcryptHash(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

// newGuardTestAPI builds a minimal *API sufficient to exercise guard's
// request flow -- only cfg and authn are ever touched by it -- configuring
// exactly one resource/action (snapshot.create) so every other resource/
// action is deliberately left unconfigured for the 404 test below.
func newGuardTestAPI(t *testing.T) *API {
	t.Helper()
	authn, err := auth.New(config.AuthConfig{
		Basic: map[string]string{"alice": mustBcryptHash(t, "s3cret")},
	}, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return &API{
		cfg: &config.Config{
			API: map[string]map[string][]string{
				ResSnapshot: {ActCreate: {"alice"}},
			},
		},
		authn: authn,
	}
}

func okHandler(w http.ResponseWriter, r *http.Request, _ auth.Identity) {
	w.WriteHeader(http.StatusOK)
}

func TestGuard_UnconfiguredActionReturns404(t *testing.T) {
	a := newGuardTestAPI(t)
	// cleanup.run is not present in cfg.API at all.
	h := a.guard(ResCleanup, ActRun, okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cleanup", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", rec.Code)
	}
}

func TestGuard_NoCredentialsReturns401(t *testing.T) {
	a := newGuardTestAPI(t)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected a WWW-Authenticate header on 401")
	}
}

func TestGuard_InvalidCredentialsReturns403(t *testing.T) {
	a := newGuardTestAPI(t)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	req.SetBasicAuth("alice", "wrong-password")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want 403", rec.Code)
	}
}

func TestGuard_ValidButNotAllowListedReturns403(t *testing.T) {
	authn, err := auth.New(config.AuthConfig{
		Basic: map[string]string{"bob": mustBcryptHash(t, "s3cret")},
	}, nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	a := &API{
		cfg: &config.Config{
			API: map[string]map[string][]string{ResSnapshot: {ActCreate: {"alice"}}},
		},
		authn: authn,
	}
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	req.SetBasicAuth("bob", "s3cret") // valid credentials, but bob isn't allow-listed
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want 403", rec.Code)
	}
}

func TestGuard_AllowedCredentialsReach2xx(t *testing.T) {
	a := newGuardTestAPI(t)
	h := a.guard(ResSnapshot, ActCreate, okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	req.SetBasicAuth("alice", "s3cret")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
}

func TestGuard_IdentityPassedToHandler(t *testing.T) {
	a := newGuardTestAPI(t)
	var got auth.Identity
	h := a.guard(ResSnapshot, ActCreate, func(w http.ResponseWriter, r *http.Request, identity auth.Identity) {
		got = identity
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/snapshot", nil)
	req.SetBasicAuth("alice", "s3cret")
	rec := httptest.NewRecorder()
	h(rec, req)

	if got.Name != "alice" || got.Method != "basic" {
		t.Fatalf("got identity %+v", got)
	}
}

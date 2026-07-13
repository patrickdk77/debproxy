package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/debproxy/debproxy/internal/auth"
	"github.com/debproxy/debproxy/internal/config"
)

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"n":   b64url(pub.N.Bytes()),
		"e":   b64url(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// oidcTestServer serves a minimal OIDC discovery document and JWKS endpoint.
// jwks is swappable mid-test (see keys field) to simulate key rotation.
type oidcTestServer struct {
	*httptest.Server
	algs        []string
	keys        atomic.Value // []map[string]string (JWKS "keys" entries)
	jwksFetches atomic.Int64
}

func newOIDCTestServer(t *testing.T, algs []string) *oidcTestServer {
	t.Helper()
	s := &oidcTestServer{algs: algs}
	s.keys.Store([]map[string]string{})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jwks_uri":                              s.URL + "/jwks.json",
			"id_token_signing_alg_values_supported": s.algs,
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		s.jwksFetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": s.keys.Load()})
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *oidcTestServer) setKeys(keys ...map[string]string) { s.keys.Store(keys) }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

// signHS256WithRSAPublicKeyAsSecret builds the classic algorithm-confusion
// attack: a token claiming HS256, "signed" using the RSA public key's own
// bytes as if they were an HMAC secret (a real attacker gets the public key
// from the JWKS endpoint itself). Should be rejected outright because the
// issuer's resolved algorithm set (from discovery, filtered through
// SafeAlgs) never includes HS256 -- SafeAlgs excludes every symmetric
// algorithm unconditionally.
func signHS256WithRSAPublicKeyAsSecret(t *testing.T, pub *rsa.PublicKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = kid
	secret := pub.N.Bytes()
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign HS256 token: %v", err)
	}
	return s
}

func bearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func newTestAuthenticator(t *testing.T, srv *oidcTestServer, issuerCfg config.OIDCIssuer) *auth.Authenticator {
	t.Helper()
	issuerCfg.Issuer = srv.URL
	a, err := auth.New(config.AuthConfig{
		OIDC: config.OIDCConfig{
			Issuers: []config.OIDCIssuer{issuerCfg},
		},
	}, srv.Client())
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func baseIssuerCfg() config.OIDCIssuer {
	return config.OIDCIssuer{
		ID:               "test-issuer",
		Audience:         "https://api.example.com",
		UsernameTemplate: "{repository}",
		GroupTemplates:   []string{"{repository_owner}"},
		MatchClaim:       "repository",
		Allow:            []string{"your-org/your-repo"},
	}
}

func baseClaims(issuer string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":              issuer,
		"aud":              "https://api.example.com",
		"exp":              time.Now().Add(time.Hour).Unix(),
		"iat":              time.Now().Unix(),
		"repository":       "your-org/your-repo",
		"repository_owner": "your-org",
	}
}

func TestOIDC_Success(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	token := signRS256(t, key, "kid-1", baseClaims(srv.URL))

	identity, err := a.Authenticate(bearerRequest(token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.Name != "your-org/your-repo" {
		t.Fatalf("got name %q", identity.Name)
	}
	if len(identity.Groups) != 1 || identity.Groups[0] != "your-org" {
		t.Fatalf("got groups %v", identity.Groups)
	}
	if identity.Method != "oidc" {
		t.Fatalf("got method %q", identity.Method)
	}
}

func TestOIDC_WrongAudienceRejected(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	claims := baseClaims(srv.URL)
	claims["aud"] = "https://someone-else.example.com"
	token := signRS256(t, key, "kid-1", claims)

	if _, err := a.Authenticate(bearerRequest(token)); err == nil {
		t.Fatal("expected an error for a token with the wrong audience")
	}
}

func TestOIDC_ExpiredTokenRejected(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	claims := baseClaims(srv.URL)
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := signRS256(t, key, "kid-1", claims)

	if _, err := a.Authenticate(bearerRequest(token)); err == nil {
		t.Fatal("expected an error for an expired token")
	}
}

func TestOIDC_NotAllowListedRejected(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	claims := baseClaims(srv.URL)
	claims["repository"] = "some-other-org/some-other-repo"
	token := signRS256(t, key, "kid-1", claims)

	if _, err := a.Authenticate(bearerRequest(token)); err == nil {
		t.Fatal("expected an error for a claim value not on the allow list")
	}
}

func TestOIDC_AlgConfusionHS256Rejected(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	token := signHS256WithRSAPublicKeyAsSecret(t, &key.PublicKey, "kid-1", baseClaims(srv.URL))

	if _, err := a.Authenticate(bearerRequest(token)); err == nil {
		t.Fatal("expected the classic RSA-public-key-as-HMAC-secret algorithm-confusion attack to be rejected")
	}
}

func TestOIDC_UnknownIssuerRejected(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	claims := baseClaims("https://not-a-configured-issuer.example.com")
	token := signRS256(t, key, "kid-1", claims)

	if _, err := a.Authenticate(bearerRequest(token)); err == nil {
		t.Fatal("expected an error for a token from an untrusted issuer")
	}
}

func TestOIDC_DiscoveryFiltersUnsafeAlgorithms(t *testing.T) {
	// The issuer's discovery document advertises HS256 alongside RS256;
	// SafeAlgs must filter HS256 out regardless, so a token claiming HS256
	// is still rejected even though the (misconfigured, or malicious)
	// discovery document names it as supported.
	srv := newOIDCTestServer(t, []string{"HS256", "RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	token := signHS256WithRSAPublicKeyAsSecret(t, &key.PublicKey, "kid-1", baseClaims(srv.URL))

	if _, err := a.Authenticate(bearerRequest(token)); err == nil {
		t.Fatal("expected HS256 to be rejected even when discovery names it as supported")
	}
}

func TestOIDC_RetriesOnceAfterKeyRotation(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	oldKey := newRSAKey(t)
	newKey := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-old", &oldKey.PublicKey)) // JWKS only has the old key cached

	a := newTestAuthenticator(t, srv, baseIssuerCfg())

	// Prime the cache with the old JWKS via an old-key token.
	oldToken := signRS256(t, oldKey, "kid-old", baseClaims(srv.URL))
	if _, err := a.Authenticate(bearerRequest(oldToken)); err != nil {
		t.Fatalf("priming Authenticate: %v", err)
	}

	// Simulate key rotation server-side: JWKS now serves the new key under a
	// new kid. A token signed with the new key should still verify, via the
	// retry-once-after-forced-rediscovery path (the cached JWKS from the
	// priming call above has no entry for "kid-new").
	srv.setKeys(rsaJWK("kid-new", &newKey.PublicKey))
	newToken := signRS256(t, newKey, "kid-new", baseClaims(srv.URL))

	identity, err := a.Authenticate(bearerRequest(newToken))
	if err != nil {
		t.Fatalf("expected retry-after-key-miss to succeed, got: %v", err)
	}
	if identity.Name != "your-org/your-repo" {
		t.Fatalf("got name %q", identity.Name)
	}
}

func TestOIDC_CachesVerificationResult(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	key := newRSAKey(t)
	srv.setKeys(rsaJWK("kid-1", &key.PublicKey))

	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	token := signRS256(t, key, "kid-1", baseClaims(srv.URL))

	if _, err := a.Authenticate(bearerRequest(token)); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
	fetchesAfterFirst := srv.jwksFetches.Load()
	if fetchesAfterFirst == 0 {
		t.Fatal("expected at least one JWKS fetch for the first call")
	}

	if _, err := a.Authenticate(bearerRequest(token)); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}
	if got := srv.jwksFetches.Load(); got != fetchesAfterFirst {
		t.Fatalf("expected no additional JWKS fetch on a cached token, got %d more", got-fetchesAfterFirst)
	}
}

func TestOIDC_ExplicitAlgorithmsRejectsUnsafe(t *testing.T) {
	cfg := config.OIDCIssuer{Algorithms: []string{"HS256"}}
	_, err := auth.New(config.AuthConfig{
		OIDC: config.OIDCConfig{Issuers: []config.OIDCIssuer{withRequiredFields(cfg, "https://issuer.example.com")}},
	}, nil)
	if err == nil {
		t.Fatal("expected auth.New to reject an issuer explicitly configured with an unsafe algorithm")
	}
}

func withRequiredFields(cfg config.OIDCIssuer, issuer string) config.OIDCIssuer {
	cfg.Issuer = issuer
	if cfg.MatchClaim == "" {
		cfg.MatchClaim = "sub"
	}
	if cfg.UsernameTemplate == "" {
		cfg.UsernameTemplate = "{sub}"
	}
	return cfg
}

func TestOIDC_JWKSURIBypassesDiscovery(t *testing.T) {
	key := newRSAKey(t)
	mux := http.NewServeMux()
	var jwksFetches atomic.Int64
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		t.Error("discovery endpoint should never be hit when jwks_uri is explicitly configured")
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwksFetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{rsaJWK("kid-1", &key.PublicKey)}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	issuerCfg := baseIssuerCfg()
	issuerCfg.JWKSURI = srv.URL + "/jwks.json"
	a := newTestAuthenticator(t, &oidcTestServer{Server: srv}, issuerCfg)

	token := signRS256(t, key, "kid-1", baseClaims(srv.URL))
	if _, err := a.Authenticate(bearerRequest(token)); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if jwksFetches.Load() == 0 {
		t.Fatal("expected the explicit jwks_uri to be fetched")
	}
}

func TestPeekIssuer_MalformedTokenNeverPanics(t *testing.T) {
	srv := newOIDCTestServer(t, []string{"RS256"})
	a := newTestAuthenticator(t, srv, baseIssuerCfg())
	for _, bad := range []string{"", "not-a-jwt", "a.b", "a.b.c.d", fmt.Sprintf("a.%s.c", b64url([]byte("{not json")))} {
		if _, err := a.Authenticate(bearerRequest(bad)); err == nil {
			t.Fatalf("expected malformed token %q to be rejected", bad)
		}
	}
}

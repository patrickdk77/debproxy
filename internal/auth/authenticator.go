package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/debproxy/debproxy/internal/config"
)

// Identity is the authenticated principal a successful Authenticate call
// resolves to.
type Identity struct {
	Name   string
	Groups []string
	// Method is "basic" or "oidc", for logging.
	Method string
}

// ErrNoCredentials is returned by Authenticate when the request has no
// Authorization header at all.
var ErrNoCredentials = errors.New("auth: no credentials supplied")

// Authenticator resolves an HTTP request's Authorization header (Basic or
// Bearer) to an Identity. There is no anonymous tier: every non-success is a
// hard authentication failure, and a Bearer token matching a configured
// issuer that fails verification never falls through to try anything else.
type Authenticator struct {
	basic             *basicVerifier
	issuers           map[string]*issuerState // keyed by issuer URL
	cache             *resultCache
	clockTolerance    time.Duration
	discoveryCooldown time.Duration
}

const (
	defaultClockToleranceSeconds    = 30
	defaultDiscoveryCooldownSeconds = 30
	defaultCacheTTLSeconds          = 300
	defaultCacheMaxEntries          = 1000
)

// New constructs an Authenticator from cfg, validating every configured
// Basic password hash format and OIDC issuer up front (fail loud at startup
// on a config mistake, not on the first request that hits it). client is
// used for OIDC discovery and JWKS fetches; a nil client gets a 10-second
// default timeout.
func New(cfg config.AuthConfig, client *http.Client) (*Authenticator, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	basic, err := newBasicVerifier(cfg.Basic)
	if err != nil {
		return nil, err
	}

	clockTolerance := time.Duration(cfg.OIDC.ClockToleranceSeconds) * time.Second
	if cfg.OIDC.ClockToleranceSeconds == 0 {
		clockTolerance = defaultClockToleranceSeconds * time.Second
	}
	discoveryCooldown := time.Duration(cfg.OIDC.DiscoveryCooldownSeconds) * time.Second
	if cfg.OIDC.DiscoveryCooldownSeconds == 0 {
		discoveryCooldown = defaultDiscoveryCooldownSeconds * time.Second
	}
	cacheTTL := time.Duration(cfg.OIDC.CacheTTLSeconds) * time.Second
	if cfg.OIDC.CacheTTLSeconds == 0 {
		cacheTTL = defaultCacheTTLSeconds * time.Second
	}
	cacheMax := cfg.OIDC.CacheMaxEntries
	if cacheMax == 0 {
		cacheMax = defaultCacheMaxEntries
	}

	issuers := map[string]*issuerState{}
	for _, ic := range cfg.OIDC.Issuers {
		if ic.Issuer == "" {
			return nil, fmt.Errorf("auth.oidc issuer %q: issuer is required", ic.ID)
		}
		if _, dup := issuers[ic.Issuer]; dup {
			return nil, fmt.Errorf("auth.oidc: duplicate issuer URL %q", ic.Issuer)
		}
		if ic.MatchClaim == "" {
			return nil, fmt.Errorf("auth.oidc issuer %q: match_claim is required", ic.ID)
		}
		if ic.UsernameTemplate == "" {
			return nil, fmt.Errorf("auth.oidc issuer %q: username_template is required", ic.ID)
		}
		st, err := newIssuerState(ic, client)
		if err != nil {
			return nil, err
		}
		issuers[ic.Issuer] = st
	}

	return &Authenticator{
		basic:             basic,
		issuers:           issuers,
		cache:             newResultCache(cacheTTL, cacheMax),
		clockTolerance:    clockTolerance,
		discoveryCooldown: discoveryCooldown,
	}, nil
}

// Authenticate resolves r's Authorization header to an Identity.
func (a *Authenticator) Authenticate(r *http.Request) (Identity, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return Identity{}, ErrNoCredentials
	}
	if user, pass, ok := r.BasicAuth(); ok {
		if a.basic.verify(user, pass) {
			return Identity{Name: user, Method: "basic"}, nil
		}
		return Identity{}, fmt.Errorf("auth: invalid basic credentials")
	}
	const bearerPrefix = "Bearer "
	if strings.HasPrefix(header, bearerPrefix) {
		token := strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
		if token == "" {
			return Identity{}, fmt.Errorf("auth: empty bearer token")
		}
		return a.verifyBearer(r.Context(), token)
	}
	return Identity{}, fmt.Errorf("auth: unrecognized Authorization scheme")
}

func (a *Authenticator) verifyBearer(ctx context.Context, token string) (Identity, error) {
	if identity, ok := a.cache.get(token); ok {
		return identity, nil
	}
	iss := peekIssuer(token)
	st, ok := a.issuers[iss]
	if !ok {
		return Identity{}, fmt.Errorf("auth: token issuer %q is not trusted", iss)
	}
	identity, expiresAt, err := st.verify(ctx, token, a.clockTolerance, a.discoveryCooldown)
	if err != nil {
		return Identity{}, err
	}
	a.cache.set(token, identity, expiresAt)
	return identity, nil
}

// peekIssuer reads a JWT's `iss` claim WITHOUT verifying anything, used only
// to pick which issuerState (if any) should attempt full verification.
// issuerState.verify re-checks iss/aud/exp/alg cryptographically; nothing
// here is trusted.
func peekIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Iss
}

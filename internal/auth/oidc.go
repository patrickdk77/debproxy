package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/debproxy/debproxy/internal/config"
)

// defaultOIDCAlgorithms is used whenever an issuer has no explicit
// `algorithms` config and no safe algorithm could be determined from OIDC
// discovery (field absent, malformed, or nothing in it survives the
// SafeAlgs filter) -- matches the reference Node/Verdaccio OIDC plugin's
// DEFAULT_ALGORITHMS.
var defaultOIDCAlgorithms = []string{"RS256"}

// errJWKSKeyMiss is a sentinel returned by an issuerState's keyfunc when a
// token's `kid` isn't found among its currently-cached JWKS keys. Retrying
// verification once, after a forced discovery+JWKS refresh, is only ever
// triggered by this specific error -- never by a bad-token error (wrong
// signature, expired, wrong audience) -- mirroring the reference plugin's
// NON_RETRYABLE_JWT_ERROR_CODES split.
var errJWKSKeyMiss = errors.New("auth: no matching JWKS key for token's kid")

var templatePlaceholder = regexp.MustCompile(`\{(\w+)\}`)

// issuerState holds one trusted issuer's resolved JWKS URI, signing
// algorithms, and cached keys, plus its allow-list matching config. All
// fields under mu are lazily resolved on first use and refreshed on a
// verification failure that looks like a stale JWKS location (see verify).
type issuerState struct {
	cfg    config.OIDCIssuer
	client *http.Client

	allow           []string // cfg.Allow, pre-folded (":" -> "/")
	caseInsensitive bool

	mu            sync.Mutex
	jwksURI       string
	algorithms    []string
	keys          map[string]crypto.PublicKey
	lastDiscovery time.Time
}

func newIssuerState(cfg config.OIDCIssuer, client *http.Client) (*issuerState, error) {
	if cfg.Algorithms != nil {
		if err := ValidateAlgorithms(cfg.Algorithms); err != nil {
			return nil, fmt.Errorf("issuer %q: %w", cfg.ID, err)
		}
	}
	ci := true
	if cfg.MatchCaseInsensitive != nil {
		ci = *cfg.MatchCaseInsensitive
	}
	allow := make([]string, len(cfg.Allow))
	for i, p := range cfg.Allow {
		allow[i] = foldDelimiters(p)
	}
	return &issuerState{cfg: cfg, client: client, allow: allow, caseInsensitive: ci}, nil
}

// resolve determines this issuer's JWKS URI and signing algorithms:
// algorithm precedence is explicit config > jwks_uri-override (default
// RS256, since bypassing discovery means there's no
// id_token_signing_alg_values_supported to consult) > discovery filtered
// through SafeAlgs > RS256 fallback.
func (s *issuerState) resolve(ctx context.Context) (jwksURI string, algorithms []string, err error) {
	if s.cfg.JWKSURI != "" {
		algs := s.cfg.Algorithms
		if len(algs) == 0 {
			algs = defaultOIDCAlgorithms
		}
		return s.cfg.JWKSURI, algs, nil
	}
	doc, err := fetchDiscovery(ctx, s.client, s.cfg.Issuer)
	if err != nil {
		return "", nil, err
	}
	algs := s.cfg.Algorithms
	if len(algs) == 0 {
		var safe []string
		for _, a := range doc.IDTokenSigningAlgValuesSupported {
			if SafeAlgs[a] {
				safe = append(safe, a)
			}
		}
		if len(safe) == 0 {
			safe = defaultOIDCAlgorithms
		}
		algs = safe
	}
	return doc.JWKSURI, algs, nil
}

// getKeys returns this issuer's currently-cached JWKS keys and algorithms,
// resolving (and, on forceRefresh, re-resolving from scratch -- including
// re-running OIDC discovery, not just refetching the same JWKS URI, since
// the provider may have moved jwks_uri, not just rotated the keys served at
// the URL already cached) on first use or after a forced refresh.
func (s *issuerState) getKeys(ctx context.Context, forceRefresh bool) (map[string]crypto.PublicKey, []string, error) {
	if forceRefresh {
		s.mu.Lock()
		s.jwksURI = ""
		s.keys = nil
		s.mu.Unlock()
	}

	s.mu.Lock()
	if s.keys != nil {
		keys, algs := s.keys, s.algorithms
		s.mu.Unlock()
		return keys, algs, nil
	}
	s.mu.Unlock()

	uri, algs, err := s.resolve(ctx)
	if err != nil {
		return nil, nil, err
	}
	keys, err := fetchJWKS(ctx, s.client, uri)
	if err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	s.jwksURI = uri
	s.algorithms = algs
	s.keys = keys
	s.mu.Unlock()
	return keys, algs, nil
}

func (s *issuerState) discoveryCooldownActive(cooldown time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastDiscovery) < cooldown
}

func (s *issuerState) markDiscoveryRefreshed() {
	s.mu.Lock()
	s.lastDiscovery = time.Now()
	s.mu.Unlock()
}

// keyFunc resolves a *jwt.Token to its verification key by kid, additionally
// pinning the token's signing method to match the resolved key's concrete
// type (mirrors pdkidp/token/jwt.go's alg-confusion defense: jwt.
// WithValidMethods already restricts the alg header to this issuer's
// resolved algorithm set, but that alone doesn't stop a crafted token naming
// e.g. "ES256" while the matched key is RSA -- checking the key's own type
// closes that gap). Returns errJWKSKeyMiss for an unrecognized kid.
func keyFunc(keys map[string]crypto.PublicKey) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok {
			return nil, errJWKSKeyMiss
		}
		switch key.(type) {
		case *rsa.PublicKey:
			switch t.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
			default:
				return nil, fmt.Errorf("unexpected signing method %v for RSA key", t.Method.Alg())
			}
		case *ecdsa.PublicKey:
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %v for EC key", t.Method.Alg())
			}
		case ed25519.PublicKey:
			if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method %v for Ed25519 key", t.Method.Alg())
			}
		}
		return key, nil
	}
}

// verify validates tokenStr against this issuer -- signature, iss, aud
// (if configured), exp (required), and clock skew -- then checks the
// resulting claims' MatchClaim value against this issuer's allow list.
// Returns the resulting Identity and the token's own expiry (for the
// caller's result cache).
func (s *issuerState) verify(ctx context.Context, tokenStr string, clockTolerance, discoveryCooldown time.Duration) (Identity, time.Time, error) {
	claims := jwt.MapClaims{}
	keys, algs, err := s.getKeys(ctx, false)
	var parseErr error
	if err != nil {
		parseErr = err
	} else {
		parseErr = s.parse(tokenStr, claims, keys, algs, clockTolerance)
	}

	if parseErr != nil {
		// Retry-once-after-forced-rediscovery only on a key-miss, and only if
		// not already within this issuer's discovery cooldown window -- never
		// on a bad-token error (wrong signature, expired, wrong audience),
		// which a rediscovery could never fix and which retrying would let
		// anyone holding a trusted issuer's name spam garbage tokens to force
		// repeated discovery calls.
		if !errors.Is(parseErr, errJWKSKeyMiss) || s.discoveryCooldownActive(discoveryCooldown) {
			return Identity{}, time.Time{}, parseErr
		}
		s.markDiscoveryRefreshed()
		keys, algs, err = s.getKeys(ctx, true)
		if err != nil {
			return Identity{}, time.Time{}, err
		}
		claims = jwt.MapClaims{}
		if err := s.parse(tokenStr, claims, keys, algs, clockTolerance); err != nil {
			return Identity{}, time.Time{}, err
		}
	}

	identity, err := s.identityFromClaims(claims)
	if err != nil {
		return Identity{}, time.Time{}, err
	}
	expFloat, _ := claims["exp"].(float64)
	return identity, time.Unix(int64(expFloat), 0), nil
}

func (s *issuerState) parse(tokenStr string, claims jwt.MapClaims, keys map[string]crypto.PublicKey, algs []string, clockTolerance time.Duration) error {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(algs),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithLeeway(clockTolerance),
		jwt.WithExpirationRequired(),
	}
	if s.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(s.cfg.Audience))
	}
	_, err := jwt.NewParser(opts...).ParseWithClaims(tokenStr, claims, keyFunc(keys))
	return err
}

func (s *issuerState) identityFromClaims(claims jwt.MapClaims) (Identity, error) {
	value, ok := claims[s.cfg.MatchClaim].(string)
	if !ok {
		return Identity{}, fmt.Errorf("claim %q missing or not a string", s.cfg.MatchClaim)
	}
	folded := foldDelimiters(value)
	allowed := false
	for _, pattern := range s.allow {
		if matchFolded(pattern, folded, s.caseInsensitive) {
			allowed = true
			break
		}
	}
	if !allowed {
		return Identity{}, fmt.Errorf("claim %q value %q is not allow-listed for issuer %q", s.cfg.MatchClaim, value, s.cfg.ID)
	}

	name := renderTemplate(s.cfg.UsernameTemplate, claims)
	groups := make([]string, 0, len(s.cfg.GroupTemplates))
	for _, t := range s.cfg.GroupTemplates {
		groups = append(groups, renderTemplate(t, claims))
	}
	return Identity{Name: name, Groups: groups, Method: "oidc"}, nil
}

// matchFolded matches a pattern/value pair that have already been folded
// (":" -> "/") by the caller, so it isn't folded a second time by Match.
func matchFolded(pattern, foldedValue string, caseInsensitive bool) bool {
	re := compiledGlob(pattern, caseInsensitive)
	if re == nil {
		return false
	}
	return re.MatchString(foldedValue)
}

func renderTemplate(tmpl string, claims jwt.MapClaims) string {
	return templatePlaceholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		key := m[1 : len(m)-1]
		v, ok := claims[key]
		if !ok {
			return ""
		}
		if str, ok := v.(string); ok {
			return str
		}
		return fmt.Sprintf("%v", v)
	})
}

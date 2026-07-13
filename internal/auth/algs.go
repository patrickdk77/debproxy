package auth

import "fmt"

// SafeAlgs is the complete set of JWT signing algorithms this package will
// ever accept for OIDC bearer-token verification -- the only ones ever
// passed to jwt.WithValidMethods, regardless of what an issuer's config or
// its OIDC discovery document names. Deliberately asymmetric-only: a JWKS
// endpoint publishes PUBLIC keys, so a legitimate issuer has no reason to
// ever sign something verifiable as HS*-over-that-same-JWKS -- an
// HS*-"signed" token can only mean someone is attempting the classic
// RSA/EC-public-key-reused-as-HMAC-secret algorithm-confusion attack. "none"
// is excluded for the same reason. No config path can ever add to this set;
// see ValidateAlgorithms and oidc.go's algorithm resolution, both of which
// filter through it. Mirrors the SAFE_ALGS ceiling in the reference
// Node/Verdaccio OIDC plugin this package has full parity with.
var SafeAlgs = map[string]bool{
	"RS256": true,
	"RS384": true,
	"RS512": true,
	"PS256": true,
	"PS384": true,
	"PS512": true,
	"ES256": true,
	"ES384": true,
	"ES512": true,
	"EdDSA": true,
}

// ValidateAlgorithms returns an error naming the first algorithm in algs
// that isn't in SafeAlgs, or nil if every one of them is safe.
func ValidateAlgorithms(algs []string) error {
	for _, a := range algs {
		if !SafeAlgs[a] {
			return fmt.Errorf("unsupported algorithm %q (supported: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA)", a)
		}
	}
	return nil
}

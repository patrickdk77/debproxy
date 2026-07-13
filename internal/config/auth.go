package config

// AuthConfig configures authentication for the /api HTTP surface: HTTP Basic
// against locally-configured hashed passwords, and/or OIDC bearer tokens
// verified against configurable trusted issuers. Either or both may be
// configured; a request authenticates via whichever scheme its Authorization
// header names.
type AuthConfig struct {
	// Basic maps username -> password hash. Supported hash formats are
	// auto-detected from their prefix: $2a$/$2b$/$2$ (bcrypt), $argon2id$
	// (argon2id), $6$ (sha512crypt), $5$ (sha256crypt). Generate hashes with
	// an operator tool (e.g. htpasswd -B, mkpasswd) -- this config never
	// stores or accepts a plaintext password.
	Basic map[string]string `yaml:"basic"`
	OIDC  OIDCConfig        `yaml:"oidc"`
}

// OIDCConfig configures OIDC bearer-token verification against zero or more
// trusted issuers.
type OIDCConfig struct {
	// ClockToleranceSeconds bounds allowed clock skew when validating a
	// token's exp/iat. Defaults to 30 when zero.
	ClockToleranceSeconds int `yaml:"clock_tolerance_seconds"`
	// DiscoveryCooldownSeconds bounds how often a run of failed token
	// verifications is allowed to force a fresh OIDC discovery + JWKS
	// re-fetch for one issuer. Defaults to 30 when zero.
	DiscoveryCooldownSeconds int `yaml:"discovery_cooldown_seconds"`
	// CacheTTLSeconds bounds how long a successfully verified token's result
	// is cached (further bounded by the token's own exp). Defaults to 300
	// when zero.
	CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
	// CacheMaxEntries bounds the verified-token result cache's size.
	// Defaults to 1000 when zero.
	CacheMaxEntries int          `yaml:"cache_max_entries"`
	Issuers         []OIDCIssuer `yaml:"issuers"`
}

// OIDCIssuer configures one trusted OIDC token issuer.
type OIDCIssuer struct {
	// ID names this issuer for logging; need not be globally unique.
	ID string `yaml:"id"`
	// Issuer is the issuer URL: both the expected `iss` claim and (unless
	// JWKSURI is set) the base for OIDC discovery
	// (`{issuer}/.well-known/openid-configuration`). Must be unique across
	// every configured issuer.
	Issuer string `yaml:"issuer"`
	// Audience, if set, is required to appear in the token's `aud` claim.
	Audience string `yaml:"audience"`
	// Algorithms, if set, is the exact allowed signing algorithm set for
	// this issuer, validated at startup against the hardcoded safe ceiling
	// (see internal/auth.SafeAlgs) -- never HS*/none regardless of what's
	// configured here. If unset, algorithms are resolved from OIDC discovery
	// (filtered through the same ceiling) or, if JWKSURI bypasses discovery,
	// default to RS256 alone.
	Algorithms []string `yaml:"algorithms"`
	// JWKSURI, if set, bypasses OIDC discovery entirely and fetches keys
	// directly from this URL.
	JWKSURI string `yaml:"jwks_uri"`
	// UsernameTemplate renders the resulting Identity's name from the
	// token's claims, e.g. "{repository}" or "svc-{sub}". "{claim}"
	// placeholders are replaced with that claim's value (stringified if not
	// already a string); an absent claim renders as empty.
	UsernameTemplate string `yaml:"username_template"`
	// GroupTemplates renders the resulting Identity's groups the same way
	// UsernameTemplate renders its name.
	GroupTemplates []string `yaml:"group_templates"`
	// MatchClaim is the token claim checked against Allow -- e.g. GitHub
	// Actions' "repository", or any other free-form claim this issuer's
	// tokens carry.
	MatchClaim string `yaml:"match_claim"`
	// MatchCaseInsensitive controls whether Allow patterns match
	// case-insensitively. nil (unset) means true.
	MatchCaseInsensitive *bool `yaml:"match_case_insensitive"`
	// Allow lists glob patterns (see internal/auth.Match) checked against
	// MatchClaim's value. A token whose claim value matches none of these is
	// rejected outright, before any api: permission check even runs.
	Allow []string `yaml:"allow"`
}

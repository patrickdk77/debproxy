package api

import "github.com/debproxy/debproxy/internal/auth"

// Allowed reports whether identity matches any of rules -- each checked
// against both identity.Name and every one of identity.Groups via
// auth.Match, always case-insensitively (per the design doc's resolved
// decision). A literal like "ci-bot" is just a glob with no wildcards (exact
// match), so Basic usernames and OIDC identity/group globs coexist in one
// list with no special-casing.
func Allowed(rules []string, identity auth.Identity) bool {
	for _, rule := range rules {
		if auth.Match(rule, identity.Name, true) {
			return true
		}
		for _, g := range identity.Groups {
			if auth.Match(rule, g, true) {
				return true
			}
		}
	}
	return false
}

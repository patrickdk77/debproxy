package auth

import (
	"regexp"
	"strings"
	"sync"
)

// Match reports whether value matches glob pattern, case-insensitively if
// caseInsensitive is true. This is the one hand-rolled glob implementation
// shared by the OIDC issuer allow list and the api: permission map
// (internal/api's Allowed): a literal like "username1" is just a glob with
// no wildcards (exact match), so Basic usernames and OIDC identity/group
// globs (e.g. "your-org/service-*") coexist in the same list with no
// special-casing.
//
// Both pattern and value are folded (":" -> "/") before matching, so "*"
// stops at a ":" delimiter exactly like it already stops at "/" -- matters
// for a claim shaped like "org:repo" (":"-delimited) the same way it matters
// for one shaped like "org/repo" ("/"-delimited). "**" crosses both.
// "?" matches exactly one non-"/" character. Any other character is matched
// literally. An invalid pattern never matches (fails closed) rather than
// erroring, since a permission check has no good way to surface a compile
// error to its caller.
func Match(pattern, value string, caseInsensitive bool) bool {
	re := compiledGlob(pattern, caseInsensitive)
	if re == nil {
		return false
	}
	return re.MatchString(foldDelimiters(value))
}

func foldDelimiters(s string) string {
	return strings.ReplaceAll(s, ":", "/")
}

type globCacheKey struct {
	pattern string
	ci      bool
}

var globCache sync.Map // globCacheKey -> *regexp.Regexp (nil entries not stored; see compiledGlob)

// compiledGlob returns the compiled regexp for pattern, memoized since this
// runs on every authenticated /api request against every configured
// permission-list entry. Returns nil if pattern fails to compile.
func compiledGlob(pattern string, caseInsensitive bool) *regexp.Regexp {
	key := globCacheKey{pattern, caseInsensitive}
	if v, ok := globCache.Load(key); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := translateGlob(pattern, caseInsensitive)
	if err != nil {
		return nil
	}
	globCache.Store(key, re)
	return re
}

func translateGlob(pattern string, caseInsensitive bool) (*regexp.Regexp, error) {
	folded := foldDelimiters(pattern)
	var b strings.Builder
	b.WriteByte('^')
	if caseInsensitive {
		b.WriteString("(?i)")
	}
	runes := []rune(folded)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(runes[i])))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

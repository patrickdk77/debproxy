package debversion

import "strings"

// Compare returns -1, 0, or 1 comparing two Debian package versions per the
// algorithm in Debian Policy 5.6.12.
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)

	if c := compareInt(ea, eb); c != 0 {
		return c
	}
	if c := compareVer(ua, ub); c != 0 {
		return c
	}
	return compareVer(ra, rb)
}

func split(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	epoch = 0
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e := parseInt(v[:i]); e >= 0 {
			epoch = e
		}
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream = v[:i]
		revision = v[i+1:]
	} else {
		upstream = v
		revision = "0"
	}
	return epoch, upstream, revision
}

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// compareVer implements the dpkg version-part comparison.
func compareVer(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		// Non-digit lexical part.
		ai, bi := 0, 0
		for ai < len(a) && !isDigit(a[ai]) {
			ai++
		}
		for bi < len(b) && !isDigit(b[bi]) {
			bi++
		}
		if c := compareLexical(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a, b = a[ai:], b[bi:]

		// Digit part.
		aj, bj := 0, 0
		for aj < len(a) && isDigit(a[aj]) {
			aj++
		}
		for bj < len(b) && isDigit(b[bj]) {
			bj++
		}
		if c := compareNumeric(a[:aj], b[:bj]); c != 0 {
			return c
		}
		a, b = a[aj:], b[bj:]
	}
	return 0
}

func compareLexical(a, b string) int {
	i := 0
	for i < len(a) || i < len(b) {
		var ca, cb int
		if i < len(a) {
			ca = order(a[i])
		} else {
			ca = 0
		}
		if i < len(b) {
			cb = order(b[i])
		} else {
			cb = 0
		}
		if ca != cb {
			return compareIntPrim(ca, cb)
		}
		i++
	}
	return 0
}

func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return compareIntPrim(len(a), len(b))
	}
	return strings.Compare(a, b)
}

// order assigns dpkg sort priority: '~' sorts before everything (even empty),
// letters sort before non-letter punctuation.
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case isAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareIntPrim(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

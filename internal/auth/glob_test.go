package auth_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/auth"
)

func TestMatch_ExactLiteral(t *testing.T) {
	if !auth.Match("ci-bot", "ci-bot", true) {
		t.Fatal("expected exact literal match")
	}
	if auth.Match("ci-bot", "ci-bot2", true) {
		t.Fatal("expected no match for a longer string")
	}
}

func TestMatch_StarStopsAtSlash(t *testing.T) {
	if !auth.Match("your-org/*", "your-org/service-a", true) {
		t.Fatal("expected * to match within one path segment")
	}
	if auth.Match("your-org/*", "your-org/service-a/extra", true) {
		t.Fatal("expected * to stop at /")
	}
}

func TestMatch_StarStopsAtColon(t *testing.T) {
	// ":" is folded to "/" before matching, so "*" stops at ":" exactly like
	// it already stops at "/" -- matters for a claim shaped like "org:repo".
	if !auth.Match("your-org:*", "your-org:service-a", true) {
		t.Fatal("expected * to match within one colon-delimited segment")
	}
	if auth.Match("your-org:*", "your-org:service-a:extra", true) {
		t.Fatal("expected * to stop at :")
	}
	// Cross-delimiter equivalence: a pattern written with "/" matches a
	// value delimited with ":" and vice versa, since both fold to "/".
	if !auth.Match("your-org/*", "your-org:service-a", true) {
		t.Fatal("expected / pattern to match a :-delimited value")
	}
}

func TestMatch_DoubleStarCrossesDelimiters(t *testing.T) {
	if !auth.Match("your-org/**", "your-org/service-a/extra/more", true) {
		t.Fatal("expected ** to cross /")
	}
	if !auth.Match("your-org/**", "your-org:service-a:extra", true) {
		t.Fatal("expected ** to cross :")
	}
}

func TestMatch_QuestionMarkSingleChar(t *testing.T) {
	if !auth.Match("service-?", "service-a", true) {
		t.Fatal("expected ? to match exactly one character")
	}
	if auth.Match("service-?", "service-ab", true) {
		t.Fatal("expected ? to match only one character")
	}
	if auth.Match("service-?", "service-/", true) {
		t.Fatal("expected ? not to match a delimiter")
	}
}

func TestMatch_CaseSensitivity(t *testing.T) {
	if !auth.Match("Your-Org/*", "your-org/service-a", true) {
		t.Fatal("expected case-insensitive match when requested")
	}
	if auth.Match("Your-Org/*", "your-org/service-a", false) {
		t.Fatal("expected case-sensitive match to fail on case mismatch")
	}
	if !auth.Match("Your-Org/*", "Your-Org/service-a", false) {
		t.Fatal("expected case-sensitive match to succeed on exact case")
	}
}

func TestMatch_LiteralCharactersEscaped(t *testing.T) {
	// "." and other regex metacharacters in a pattern must be matched
	// literally, not as regex syntax.
	if !auth.Match("service.a", "service.a", true) {
		t.Fatal("expected literal . to match itself")
	}
	if auth.Match("service.a", "serviceXa", true) {
		t.Fatal("expected literal . not to match any character")
	}
}

func TestMatch_EmptyPatternOnlyMatchesEmptyValue(t *testing.T) {
	if !auth.Match("", "", true) {
		t.Fatal("expected empty pattern to match empty value")
	}
	if auth.Match("", "x", true) {
		t.Fatal("expected empty pattern not to match a non-empty value")
	}
}

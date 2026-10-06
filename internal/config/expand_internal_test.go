package config

import (
	"os"
	"testing"
)

func TestExpandURLEnvRefsExpandsVariables(t *testing.T) {
	t.Setenv("DEBPROXY_TEST_PW", "s3cret")
	got := expandURLEnvRefs("valkey://u:$DEBPROXY_TEST_PW@h:6379/0")
	want := "valkey://u:s3cret@h:6379/0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got = expandURLEnvRefs("valkey://u:${DEBPROXY_TEST_PW}@h:6379/0")
	if got != want {
		t.Errorf("braced form: got %q, want %q", got, want)
	}
}

// TestExpandURLEnvRefsDollarEscape is the regression test: a literal "$"
// in a credential used to be read as a variable reference and replaced
// with nothing. "$$" must survive as one "$" and never be expanded.
func TestExpandURLEnvRefsDollarEscape(t *testing.T) {
	t.Setenv("PRICE", "should-not-appear")
	got := expandURLEnvRefs("valkey://u:pa$$PRICE@h/0")
	want := "valkey://u:pa$PRICE@h/0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpandURLEnvRefsMixedEscapeAndRef(t *testing.T) {
	t.Setenv("DEBPROXY_TEST_PW", "x")
	got := expandURLEnvRefs("a$$b$DEBPROXY_TEST_PW$$")
	if got != "a$bx$" {
		t.Errorf("got %q, want %q", got, "a$bx$")
	}
}

func TestExpandURLEnvRefsUnsetVariableIsEmpty(t *testing.T) {
	// Unchanged behavior, pinned so the escape work does not alter it.
	os.Unsetenv("DEBPROXY_DEFINITELY_UNSET_VAR")
	if got := expandURLEnvRefs("x$DEBPROXY_DEFINITELY_UNSET_VAR"); got != "x" {
		t.Errorf("got %q, want %q", got, "x")
	}
}

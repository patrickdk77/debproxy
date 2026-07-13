package api_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/api"
	"github.com/debproxy/debproxy/internal/auth"
)

func TestAllowed_ExactUsernameMatch(t *testing.T) {
	rules := []string{"ci-bot", "admin"}
	if !api.Allowed(rules, auth.Identity{Name: "ci-bot"}) {
		t.Fatal("expected exact username match to be allowed")
	}
	if api.Allowed(rules, auth.Identity{Name: "someone-else"}) {
		t.Fatal("expected an unlisted username to be denied")
	}
}

func TestAllowed_GlobMatch(t *testing.T) {
	rules := []string{"admin-*"}
	if !api.Allowed(rules, auth.Identity{Name: "admin-alice"}) {
		t.Fatal("expected a glob rule to match a qualifying name")
	}
	if api.Allowed(rules, auth.Identity{Name: "not-admin-alice"}) {
		t.Fatal("expected a glob rule not to match a non-qualifying name")
	}
}

func TestAllowed_GroupMatch(t *testing.T) {
	rules := []string{"your-org"}
	identity := auth.Identity{Name: "your-org/your-repo", Groups: []string{"your-org"}}
	if !api.Allowed(rules, identity) {
		t.Fatal("expected a rule matching a group (not the name) to be allowed")
	}
}

func TestAllowed_CaseInsensitive(t *testing.T) {
	rules := []string{"CI-Bot"}
	if !api.Allowed(rules, auth.Identity{Name: "ci-bot"}) {
		t.Fatal("expected permission matching to be case-insensitive")
	}
}

func TestAllowed_EmptyRulesDenyEverything(t *testing.T) {
	if api.Allowed(nil, auth.Identity{Name: "anyone"}) {
		t.Fatal("expected no rules to deny everyone")
	}
}

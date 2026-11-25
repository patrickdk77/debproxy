package config_test

import (
	"strings"
	"testing"
)

func TestLoadCompilesPackageFilter(t *testing.T) {
	cfg, err := loadUpstreams(t, fsStorage, map[string]string{
		"both":  "    url: http://host/x\n    packages:\n      allow: '^hello'\n      deny: evil\n",
		"deny":  "    url: http://host/y\n    packages:\n      deny: evil\n",
		"none":  "    url: http://host/z\n",
		"empty": "    url: http://host/w\n    packages: {}\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	both := resolvedUpstream(t, cfg, "both").Filter
	if both == nil {
		t.Fatal("allow+deny: Filter is nil")
	}
	for name, want := range map[string]bool{"hello": true, "hello-tool": true, "hello-evil": false, "evil-hello": false, "other": false} {
		if got := both.Allows(name); got != want {
			t.Errorf("allow ^hello deny evil: Allows(%q) = %v, want %v", name, got, want)
		}
	}
	deny := resolvedUpstream(t, cfg, "deny").Filter
	if deny == nil || deny.Allow != nil {
		t.Fatalf("deny only: Filter = %+v, want Deny set and Allow nil", deny)
	}
	if deny.Allows("unevil") || !deny.Allows("good") {
		t.Fatal("deny only: evil should be rejected and good allowed")
	}
	for _, name := range []string{"none", "empty"} {
		if f := resolvedUpstream(t, cfg, name).Filter; f != nil {
			t.Fatalf("%s: Filter = %+v, want nil", name, f)
		}
	}
}

func TestLoadRejectsBadPackageFilterRegex(t *testing.T) {
	for _, key := range []string{"allow", "deny"} {
		t.Run(key, func(t *testing.T) {
			_, err := loadUpstreams(t, fsStorage, map[string]string{"up": "    url: http://host/x\n    packages:\n      " + key + ": '('\n"})
			if err == nil {
				t.Fatal("expected Load to reject an unbalanced regex, got nil error")
			}
			if !strings.Contains(err.Error(), "packages."+key) {
				t.Fatalf("error does not name packages.%s: %v", key, err)
			}
		})
	}
}

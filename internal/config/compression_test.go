package config_test

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/debproxy/debproxy/internal/config"
)

type resolvedCompression struct {
	GZip, ZStd int
	XZ         bool
}

func resolveCompression(t *testing.T, yamlSnippet string) (snapshot, live resolvedCompression) {
	t.Helper()
	var cc config.CompressionConfig
	if err := yaml.Unmarshal([]byte(yamlSnippet), &cc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rs := cc.ResolveSnapshot()
	rl := cc.ResolveLive()
	snapshot.GZip, snapshot.ZStd, snapshot.XZ = rs.GZip, rs.ZStd, rs.XZ
	live.GZip, live.ZStd, live.XZ = rl.GZip, rl.ZStd, rl.XZ
	return
}

func TestCompressionXZUnsetVsExplicitTrue(t *testing.T) {
	// Nothing set at all: live.xz must default to disabled, snapshot.xz to enabled.
	_, live := resolveCompression(t, ``)
	if live.XZ {
		t.Errorf("live.xz with nothing set: got enabled, want disabled (documented default)")
	}
	snapshot, _ := resolveCompression(t, ``)
	if !snapshot.XZ {
		t.Errorf("snapshot.xz with nothing set: got disabled, want enabled (documented default)")
	}

	// Explicit `true` for live.xz must now actually enable it -- this is the
	// bug: previously "true" and "absent" decoded to the identical value and
	// were indistinguishable, so this always failed before the fix.
	_, live = resolveCompression(t, "live:\n  xz: true\n")
	if !live.XZ {
		t.Error("live.xz: true must enable XZ, got disabled")
	}

	// Explicit `false` must still disable it in both modes.
	snapshot, _ = resolveCompression(t, "snapshot:\n  xz: false\n")
	if snapshot.XZ {
		t.Error("snapshot.xz: false must disable XZ, got enabled")
	}
	_, live = resolveCompression(t, "live:\n  xz: false\n")
	if live.XZ {
		t.Error("live.xz: false must disable XZ, got enabled")
	}

	// An explicit positive level also enables it (no numeric level to speak of
	// in the underlying xz library, but it must not silently do nothing).
	_, live = resolveCompression(t, "live:\n  xz: 5\n")
	if !live.XZ {
		t.Error("live.xz: 5 must enable XZ, got disabled")
	}
}

func TestCompressionGZipZStdUnsetVsTrueBehaveTheSame(t *testing.T) {
	// For GZip/ZStd, absent and explicit true both mean "use the mode's
	// built-in default level" -- this must keep working under the pointer
	// refactor exactly as it did before.
	unset, _ := resolveCompression(t, ``)
	explicitTrue, _ := resolveCompression(t, "snapshot:\n  gzip: true\n  zstd: true\n")
	if unset.GZip != explicitTrue.GZip || unset.ZStd != explicitTrue.ZStd {
		t.Errorf("unset vs explicit true should resolve identically: unset=%+v explicitTrue=%+v", unset, explicitTrue)
	}

	explicitLevel, _ := resolveCompression(t, "snapshot:\n  gzip: 4\n")
	if explicitLevel.GZip != 4 {
		t.Errorf("snapshot.gzip: 4 should resolve to level 4, got %d", explicitLevel.GZip)
	}
}

// TestCompressionGZipZStd_TrueEnablesFalseDisables proves gzip/zstd behave as
// expected in both modes: explicit true enables at the mode's default level
// (nonzero), explicit false disables (resolves to 0, which publish.go treats
// as "don't produce this variant" -- see GenerateSuite's `> 0` checks).
func TestCompressionGZipZStdTrueEnablesFalseDisables(t *testing.T) {
	for _, mode := range []string{"snapshot", "live"} {
		trueYAML := mode + ":\n  gzip: true\n  zstd: true\n"
		falseYAML := mode + ":\n  gzip: false\n  zstd: false\n"

		get := func(yamlSnippet string) resolvedCompression {
			s, l := resolveCompression(t, yamlSnippet)
			if mode == "snapshot" {
				return s
			}
			return l
		}

		enabled := get(trueYAML)
		if enabled.GZip <= 0 {
			t.Errorf("%s.gzip: true should enable gzip (positive level), got %d", mode, enabled.GZip)
		}
		if enabled.ZStd <= 0 {
			t.Errorf("%s.zstd: true should enable zstd (positive level), got %d", mode, enabled.ZStd)
		}

		disabled := get(falseYAML)
		if disabled.GZip != 0 {
			t.Errorf("%s.gzip: false should disable gzip (level 0), got %d", mode, disabled.GZip)
		}
		if disabled.ZStd != 0 {
			t.Errorf("%s.zstd: false should disable zstd (level 0), got %d", mode, disabled.ZStd)
		}
	}
}

package signing

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func writeKeyFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.asc")
	if err := os.WriteFile(p, []byte("not a real key"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies umask; force the exact mode under test.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestWarnIfKeyReadableFlagsGroupAndOther covers every mode that exposes
// the key beyond its owner.
func TestWarnIfKeyReadableFlagsGroupAndOther(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666, 0o444} {
		buf := captureSlog(t)
		warnIfKeyReadable(writeKeyFile(t, mode))
		if !strings.Contains(buf.String(), "level=WARN") {
			t.Errorf("mode %04o: no warning logged", mode)
		}
		if !strings.Contains(buf.String(), "readable by group or others") {
			t.Errorf("mode %04o: warning does not name the problem", mode)
		}
	}
}

// TestWarnIfKeyReadableSilentForOwnerOnly is the other half: a correctly
// restricted file must produce no noise.
func TestWarnIfKeyReadableSilentForOwnerOnly(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400, 0o700} {
		buf := captureSlog(t)
		warnIfKeyReadable(writeKeyFile(t, mode))
		if buf.Len() != 0 {
			t.Errorf("mode %04o: unexpected log output: %s", mode, buf.String())
		}
	}
}

// TestWarnIfKeyReadableMissingFileIsSilent confirms a stat failure is
// left for Load's own read error to report, not duplicated here.
func TestWarnIfKeyReadableMissingFileIsSilent(t *testing.T) {
	buf := captureSlog(t)
	warnIfKeyReadable(filepath.Join(t.TempDir(), "does-not-exist.asc"))
	if buf.Len() != 0 {
		t.Errorf("unexpected log output for a missing file: %s", buf.String())
	}
}

// TestLoadStillFailsOnMissingFile pins that the permission check did not
// change Load's error contract.
func TestLoadStillFailsOnMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.asc")); err == nil {
		t.Fatal("Load succeeded on a missing file")
	}
}

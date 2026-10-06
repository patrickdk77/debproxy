package storage

import (
	"strings"
	"testing"
)

func TestCleanRelPathCollapsesAllLeadingSlashes(t *testing.T) {
	for _, in := range []string{"/x", "//x", "///x", "   //x"} {
		got, err := CleanRelPath(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != "x" {
			t.Errorf("%q -> %q, want %q", in, got, "x")
		}
	}
}

// TestCleanRelPathRejectsNUL covers a byte no real path contains: the OS
// refuses it, an object store accepts it, so passing it through produces
// a key nothing can read back.
func TestCleanRelPathRejectsNUL(t *testing.T) {
	for _, in := range []string{"x\x00y", "\x00", "pool/\x00/a.deb"} {
		if _, err := CleanRelPath(in); err == nil {
			t.Errorf("%q accepted", in)
		} else if !strings.Contains(err.Error(), "NUL") {
			t.Errorf("%q: error does not name the cause: %v", in, err)
		}
	}
}

func TestCleanRelPathStillRejectsTraversal(t *testing.T) {
	for _, in := range []string{"..", "../x", "a/../../b", "/../x", "//../x"} {
		if _, err := CleanRelPath(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestCleanRelPathNormalizesWithinRoot(t *testing.T) {
	cases := map[string]string{
		"a/..":     "",
		"./x":      "x",
		"x/./y":    "x/y",
		"a/b/../c": "a/c",
		"":         "",
		"/":        "",
	}
	for in, want := range cases {
		got, err := CleanRelPath(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// TestCleanRelPathKeepsDotsThatAreNotTraversal guards against an
// over-eager fix: "..." and "a/.../b" are legal names, not parent refs.
func TestCleanRelPathKeepsDotsThatAreNotTraversal(t *testing.T) {
	for _, in := range []string{"...", "a/.../b", "..x", "x.."} {
		got, err := CleanRelPath(in)
		if err != nil {
			t.Errorf("%q rejected: %v", in, err)
		}
		if got != in {
			t.Errorf("%q -> %q, want unchanged", in, got)
		}
	}
}

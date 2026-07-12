package apt_test

import (
	"strings"
	"testing"

	"github.com/debproxy/debproxy/internal/apt"
)

func TestRawPkgWithFilenameMiddleField(t *testing.T) {
	pkg := apt.RawPkg{Raw: "Package: hello\nFilename: pool/old.deb\nVersion: 1.0\n"}
	got := pkg.WithFilename("pool/new.deb")
	want := "Package: hello\nFilename: pool/new.deb\nVersion: 1.0\n"
	if got != want {
		t.Errorf("WithFilename() = %q, want %q", got, want)
	}
}

func TestRawPkgWithFilenameFirstField(t *testing.T) {
	pkg := apt.RawPkg{Raw: "Filename: pool/old.deb\nPackage: hello\nVersion: 1.0\n"}
	got := pkg.WithFilename("pool/new.deb")
	want := "Filename: pool/new.deb\nPackage: hello\nVersion: 1.0\n"
	if got != want {
		t.Errorf("WithFilename() = %q, want %q", got, want)
	}
	if strings.Count(got, "Filename:") != 1 {
		t.Errorf("WithFilename() produced %d Filename: fields, want 1: %q", strings.Count(got, "Filename:"), got)
	}
}

func TestRawPkgWithFilenameFirstFieldOnly(t *testing.T) {
	pkg := apt.RawPkg{Raw: "Filename: pool/old.deb"}
	got := pkg.WithFilename("pool/new.deb")
	want := "Filename: pool/new.deb"
	if got != want {
		t.Errorf("WithFilename() = %q, want %q", got, want)
	}
}

func TestRawPkgWithFilenameNoExistingField(t *testing.T) {
	pkg := apt.RawPkg{Raw: "Package: hello\nVersion: 1.0\n"}
	got := pkg.WithFilename("pool/new.deb")
	want := "Filename: pool/new.deb\nPackage: hello\nVersion: 1.0\n"
	if got != want {
		t.Errorf("WithFilename() = %q, want %q", got, want)
	}
}

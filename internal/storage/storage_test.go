package storage_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/storage"
)

func TestCleanRelPathRejectsTraversal(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "pool/debian/trixie/main/h/hello/hello_1.0.deb", want: "pool/debian/trixie/main/h/hello/hello_1.0.deb"},
		{in: "/pool/debian/foo.deb", want: "pool/debian/foo.deb"},
		{in: "", want: ""},
		{in: "../../etc/passwd", wantErr: true},
		{in: "..", wantErr: true},
		{in: "pool/../../../metadata/index/debian.packages.zst", wantErr: true},
		{in: "pool/../main/foo.deb", want: "main/foo.deb"}, // resolves upward but stays within bounds
	}
	for _, c := range cases {
		got, err := storage.CleanRelPath(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("CleanRelPath(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("CleanRelPath(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("CleanRelPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

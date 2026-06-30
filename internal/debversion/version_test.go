package debversion_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/debversion"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"2.6.1", "2.6.10", -1},
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1},
		{"1.0~beta", "1.0", -1},
		{"1.0~~", "1.0~~a", -1},
		{"1.0~~a", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0~", 1},
		{"1.0a", "1.0", 1},
		{"1.0+deb12u1", "1.0+deb12u2", -1},
		{"0", "0.0", -1},
	}
	for _, c := range cases {
		got := debversion.Compare(c.a, c.b)
		if got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry.
		if rev := debversion.Compare(c.b, c.a); rev != -c.want {
			t.Errorf("Compare(%q,%q)=%d not antisymmetric (%d)", c.b, c.a, rev, got)
		}
	}
}

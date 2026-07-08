package server

import "testing"

func TestSanitizeLogFieldStripsInjection(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`normal-user-agent/1.0`, `normal-user-agent/1.0`},
		{`evil" 200 999999 "-`, `evil 200 999999 -`},
		{"has\nnewline", "hasnewline"},
		{"has\rcarriage", "hascarriage"},
		{"has\x00null", "hasnull"},
	}
	for _, c := range cases {
		if got := sanitizeLogField(c.in); got != c.want {
			t.Errorf("sanitizeLogField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

package config_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/config"
)

func TestParseSize_Disabled(t *testing.T) {
	for _, s := range []string{"", "0"} {
		n, err := config.ParseSize(s)
		if err != nil {
			t.Errorf("ParseSize(%q): unexpected error %v", s, err)
		}
		if n != 0 {
			t.Errorf("ParseSize(%q) = %d, want 0", s, n)
		}
	}
}

func TestParseSize_BareBytes(t *testing.T) {
	n, err := config.ParseSize("500")
	if err != nil {
		t.Fatalf("ParseSize: %v", err)
	}
	if n != 500 {
		t.Fatalf("got %d, want 500", n)
	}
}

func TestParseSize_Suffixes(t *testing.T) {
	cases := map[string]int64{
		"500B":  500,
		"1K":    1 << 10,
		"1KB":   1 << 10,
		"1M":    1 << 20,
		"1MB":   1 << 20,
		"1G":    1 << 30,
		"1GB":   1 << 30,
		"1gb":   1 << 30,
		"1Gb":   1 << 30,
		"2GB":   2 * (1 << 30),
		"500MB": 500 * (1 << 20),
	}
	for in, want := range cases {
		got, err := config.ParseSize(in)
		if err != nil {
			t.Errorf("ParseSize(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseSize_Fractional(t *testing.T) {
	got, err := config.ParseSize("1.5GB")
	if err != nil {
		t.Fatalf("ParseSize: %v", err)
	}
	want := int64(1.5 * (1 << 30))
	if got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

func TestParseSize_WhitespaceTolerant(t *testing.T) {
	got, err := config.ParseSize("  1 GB  ")
	if err != nil {
		t.Fatalf("ParseSize: %v", err)
	}
	if got != 1<<30 {
		t.Fatalf("got %d, want %d", got, int64(1<<30))
	}
}

func TestParseSize_Invalid(t *testing.T) {
	for _, s := range []string{"abc", "-5", "-5GB", "5XB", "GB"} {
		if _, err := config.ParseSize(s); err == nil {
			t.Errorf("ParseSize(%q): expected an error, got none", s)
		}
	}
}

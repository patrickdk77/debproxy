package server

import "testing"

func TestMetricTripleBoundsCardinality(t *testing.T) {
	s := &Server{
		validTriple: map[string]bool{
			"debian/trixie/debian-main": true,
		},
		validOSCodename: map[string]bool{
			"debian/trixie": true,
		},
	}

	if os, cn, up := s.metricTriple("debian", "trixie", "debian-main"); os != "debian" || cn != "trixie" || up != "debian-main" {
		t.Errorf("expected configured triple to pass through unchanged, got (%q, %q, %q)", os, cn, up)
	}

	// Any component not matching a configured layout -- however it's spelled --
	// must collapse to the same constant sentinel, not leak into the label set.
	cases := [][3]string{
		{"debian", "trixie", "made-up-upstream"},
		{"made-up-os", "trixie", "debian-main"},
		{"debian", "made-up-codename", "debian-main"},
		{"../../etc", "passwd", "x"},
	}
	for _, c := range cases {
		os, cn, up := s.metricTriple(c[0], c[1], c[2])
		if os != "_invalid" || cn != "_invalid" || up != "_invalid" {
			t.Errorf("metricTriple(%q, %q, %q) = (%q, %q, %q), want all _invalid", c[0], c[1], c[2], os, cn, up)
		}
	}

	if os, cn := s.metricOSCodename("debian", "trixie"); os != "debian" || cn != "trixie" {
		t.Errorf("expected configured os/codename to pass through unchanged, got (%q, %q)", os, cn)
	}
	if os, cn := s.metricOSCodename("debian", "made-up-codename"); os != "_invalid" || cn != "_invalid" {
		t.Errorf("metricOSCodename with unknown codename = (%q, %q), want _invalid pair", os, cn)
	}
}

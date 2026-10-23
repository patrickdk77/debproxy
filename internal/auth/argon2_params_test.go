package auth

import (
	"strings"
	"testing"
)

const goodArgon = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

func withParams(m, t, p string) string {
	return "$argon2id$v=19$m=" + m + ",t=" + t + ",p=" + p + "$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
}

func TestParseArgon2idAcceptsSaneParams(t *testing.T) {
	if _, err := parseArgon2id(goodArgon); err != nil {
		t.Fatalf("sane hash rejected: %v", err)
	}
}

// TestParseArgon2idRejectsPanicInducingParams is the regression test:
// these values make argon2.IDKey panic, and they used to be accepted at
// load and only blow up on the first login.
func TestParseArgon2idRejectsPanicInducingParams(t *testing.T) {
	cases := map[string]string{
		"t=0":   withParams("65536", "0", "4"),
		"p=0":   withParams("65536", "3", "0"),
		"p=256": withParams("65536", "3", "256"),
		"m<8p":  withParams("16", "3", "4"),
	}
	for name, h := range cases {
		if _, err := parseArgon2id(h); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "argon2id params") {
			t.Errorf("%s: error does not name the parameter problem: %v", name, err)
		}
	}
}

// TestVerifyArgon2idDoesNotPanicOnBadParams proves the request path is
// safe even if a bad hash somehow reaches it.
func TestVerifyArgon2idDoesNotPanicOnBadParams(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("verify panicked: %v", r)
		}
	}()
	if verifyArgon2id("password", withParams("65536", "0", "4")) {
		t.Fatal("bad hash verified as a match")
	}
}

func TestVerifyArgon2idStillRejectsWrongPassword(t *testing.T) {
	// goodArgon's hash bytes are not a real digest of any password, so
	// any password must fail; the point is it fails cleanly.
	if verifyArgon2id("anything", goodArgon) {
		t.Fatal("non-matching password verified")
	}
}

// TestNewBasicVerifierRejectsBadArgon2AtLoad moves the failure to
// startup, where an operator sees it, instead of the first login.
func TestNewBasicVerifierRejectsBadArgon2AtLoad(t *testing.T) {
	_, err := newBasicVerifier(map[string]string{"alice": withParams("65536", "0", "4")})
	if err == nil {
		t.Fatal("t=0 argon2 hash accepted at load")
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error does not name the user: %v", err)
	}
}

func TestNewBasicVerifierAcceptsGoodArgon2(t *testing.T) {
	if _, err := newBasicVerifier(map[string]string{"alice": goodArgon}); err != nil {
		t.Fatalf("sane argon2 hash rejected at load: %v", err)
	}
}

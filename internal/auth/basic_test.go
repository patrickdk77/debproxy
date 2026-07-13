package auth

import "testing"

func TestBasicVerifier_CorrectPassword(t *testing.T) {
	b, err := newBasicVerifier(map[string]string{"alice": mustBcrypt(t, "s3cret")})
	if err != nil {
		t.Fatalf("newBasicVerifier: %v", err)
	}
	if !b.verify("alice", "s3cret") {
		t.Fatal("expected correct password to verify")
	}
}

func TestBasicVerifier_WrongPassword(t *testing.T) {
	b, err := newBasicVerifier(map[string]string{"alice": mustBcrypt(t, "s3cret")})
	if err != nil {
		t.Fatalf("newBasicVerifier: %v", err)
	}
	if b.verify("alice", "wrong") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestBasicVerifier_UnknownUser(t *testing.T) {
	b, err := newBasicVerifier(map[string]string{"alice": mustBcrypt(t, "s3cret")})
	if err != nil {
		t.Fatalf("newBasicVerifier: %v", err)
	}
	if b.verify("bob", "anything") {
		t.Fatal("expected unknown user to fail")
	}
}

func TestNewBasicVerifier_RejectsUnrecognizedHash(t *testing.T) {
	_, err := newBasicVerifier(map[string]string{"alice": "plaintext-not-a-hash"})
	if err == nil {
		t.Fatal("expected an error for an unrecognized password hash format")
	}
}

func TestNewBasicVerifier_AcceptsAllFourFormats(t *testing.T) {
	_, err := newBasicVerifier(map[string]string{
		"bcrypt-user":      mustBcrypt(t, "x"),
		"argon2id-user":    mustArgon2id(t, "x"),
		"sha512crypt-user": mustSHA512Crypt(t, "x"),
		"sha256crypt-user": mustSHA256Crypt(t, "x"),
	})
	if err != nil {
		t.Fatalf("expected all four recognized hash formats to be accepted: %v", err)
	}
}

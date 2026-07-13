package auth

import (
	"encoding/base64"
	"fmt"
	"testing"

	gocrypt "github.com/GehirnInc/crypt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func mustBcrypt(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func mustArgon2id(t *testing.T, plaintext string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	hash := argon2.IDKey([]byte(plaintext), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 4,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
}

func mustSHA512Crypt(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := gocrypt.SHA512.New().Generate([]byte(plaintext), []byte("$6$testsalt1234$"))
	if err != nil {
		t.Fatalf("sha512crypt Generate: %v", err)
	}
	return h
}

func mustSHA256Crypt(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := gocrypt.SHA256.New().Generate([]byte(plaintext), []byte("$5$testsalt1234$"))
	if err != nil {
		t.Fatalf("sha256crypt Generate: %v", err)
	}
	return h
}

func TestVerifyPassword_Bcrypt(t *testing.T) {
	hash := mustBcrypt(t, "s3cret")
	if !verifyPassword("s3cret", hash) {
		t.Fatal("expected correct password to verify")
	}
	if verifyPassword("wrong", hash) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestVerifyPassword_Argon2id(t *testing.T) {
	hash := mustArgon2id(t, "s3cret")
	if !verifyPassword("s3cret", hash) {
		t.Fatal("expected correct password to verify")
	}
	if verifyPassword("wrong", hash) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestVerifyPassword_SHA512Crypt(t *testing.T) {
	hash := mustSHA512Crypt(t, "s3cret")
	if !verifyPassword("s3cret", hash) {
		t.Fatal("expected correct password to verify")
	}
	if verifyPassword("wrong", hash) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestVerifyPassword_SHA256Crypt(t *testing.T) {
	hash := mustSHA256Crypt(t, "s3cret")
	if !verifyPassword("s3cret", hash) {
		t.Fatal("expected correct password to verify")
	}
	if verifyPassword("wrong", hash) {
		t.Fatal("expected wrong password to fail")
	}
}

func TestVerifyPassword_UnrecognizedFormat(t *testing.T) {
	if verifyPassword("s3cret", "plaintext-not-a-hash") {
		t.Fatal("expected an unrecognized hash format to never verify")
	}
}

func TestRecognizedHashPrefix(t *testing.T) {
	cases := map[string]bool{
		mustBcrypt(t, "x"):      true,
		mustArgon2id(t, "x"):    true,
		mustSHA512Crypt(t, "x"): true,
		mustSHA256Crypt(t, "x"): true,
		"plaintext":             false,
		"$1$oldmd5$hash":        false,
	}
	for hash, want := range cases {
		if got := recognizedHashPrefix(hash); got != want {
			t.Errorf("recognizedHashPrefix(%q) = %v, want %v", hash, got, want)
		}
	}
}

// TestGehirnCryptDispatchesBothVariants guards against a regression where
// registering only one of sha256_crypt/sha512_crypt (both are blank-imported
// in password.go) would make gocrypt.NewFromHash silently fail to dispatch
// for the other prefix.
func TestGehirnCryptDispatchesBothVariants(t *testing.T) {
	for _, hash := range []string{mustSHA512Crypt(t, "x"), mustSHA256Crypt(t, "x")} {
		if gocrypt.NewFromHash(hash) == nil {
			t.Fatalf("NewFromHash(%q) returned nil -- crypt variant not registered", hash)
		}
	}
}

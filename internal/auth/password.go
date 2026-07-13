// Package auth implements authentication for debproxy's /api HTTP surface:
// HTTP Basic against locally-configured hashed passwords, and OIDC bearer
// tokens verified against configurable trusted issuers. See authenticator.go
// for the combined entry point.
package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	gocrypt "github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt" // register $5$ handler
	_ "github.com/GehirnInc/crypt/sha512_crypt" // register $6$ handler
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// verifyPassword checks plaintext against a stored hash, auto-detecting the
// algorithm from the hash's prefix. Near-verbatim port of
// pdkidp/password/password.go's Verify (hash generation is an operator
// concern here, via htpasswd/mkpasswd, so Hash itself isn't ported), plus a
// $5$ (sha256crypt) branch using the same GehirnInc/crypt module pdkidp
// already uses for $6$.
func verifyPassword(plaintext, hash string) bool {
	switch {
	case strings.HasPrefix(hash, "$6$"), strings.HasPrefix(hash, "$5$"):
		return verifyCrypt(plaintext, hash)
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2$"):
		return verifyBcrypt(plaintext, hash)
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2id(plaintext, hash)
	default:
		return false
	}
}

// recognizedHashPrefix reports whether hash is in one of the formats
// verifyPassword knows how to check, without actually checking it -- used at
// config load time to reject a typo'd or unsupported hash up front rather
// than have it silently fail every login attempt.
func recognizedHashPrefix(hash string) bool {
	switch {
	case strings.HasPrefix(hash, "$6$"), strings.HasPrefix(hash, "$5$"),
		strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2$"),
		strings.HasPrefix(hash, "$argon2id$"):
		return true
	}
	return false
}

// --- sha512crypt ($6$) / sha256crypt ($5$) ---

func verifyCrypt(plaintext, hash string) bool {
	c := gocrypt.NewFromHash(hash)
	if c == nil {
		return false
	}
	return c.Verify(hash, []byte(plaintext)) == nil
}

// --- bcrypt ($2a$/$2b$/$2$) ---

func verifyBcrypt(plaintext, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// --- Argon2id ($argon2id$) ---

type argon2idParams struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	hash    []byte
}

func verifyArgon2id(plaintext, encoded string) bool {
	p, err := parseArgon2id(encoded)
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(plaintext), p.salt, p.time, p.memory, p.threads, uint32(len(p.hash)))
	return subtle.ConstantTimeCompare(computed, p.hash) == 1
}

func parseArgon2id(encoded string) (*argon2idParams, error) {
	// Expected format: $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, fmt.Errorf("invalid argon2id hash format")
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, fmt.Errorf("invalid argon2id params")
	}
	memory, err := parseKV(params[0], "m")
	if err != nil {
		return nil, err
	}
	timeCost, err := parseKV(params[1], "t")
	if err != nil {
		return nil, err
	}
	threads, err := parseKV(params[2], "p")
	if err != nil {
		return nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid argon2id salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid argon2id hash: %w", err)
	}

	return &argon2idParams{
		memory:  uint32(memory),
		time:    uint32(timeCost),
		threads: uint8(threads),
		salt:    salt,
		hash:    hash,
	}, nil
}

func parseKV(s, key string) (int, error) {
	prefix := key + "="
	if !strings.HasPrefix(s, prefix) {
		return 0, fmt.Errorf("expected %s=<n>, got %q", key, s)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, prefix))
	if err != nil {
		return 0, fmt.Errorf("invalid value in %q", s)
	}
	return n, nil
}

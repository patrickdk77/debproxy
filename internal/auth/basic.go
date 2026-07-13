package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is a valid bcrypt hash of an arbitrary, never-used password,
// computed once at package init. basicVerifier.verify compares against it on
// an unknown username so that verification always costs the same real hash
// comparison whether or not the username exists -- otherwise response timing
// (an unknown username short-circuits instantly; a known one pays for a full
// bcrypt/argon2/crypt comparison) could be used to enumerate valid usernames.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := bcrypt.GenerateFromPassword([]byte("debproxy-auth-timing-safety-dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}

// basicVerifier checks HTTP Basic credentials against a fixed set of
// username -> password hash pairs loaded from config.
type basicVerifier struct {
	users map[string]string
}

func newBasicVerifier(basic map[string]string) (*basicVerifier, error) {
	for user, hash := range basic {
		if !recognizedHashPrefix(hash) {
			return nil, fmt.Errorf("auth.basic user %q: unrecognized password hash format (expected $2a$/$2b$/$2$, $argon2id$, $6$, or $5$)", user)
		}
	}
	return &basicVerifier{users: basic}, nil
}

// verify reports whether user/pass match a configured Basic user.
func (b *basicVerifier) verify(user, pass string) bool {
	hash, ok := b.users[user]
	if !ok {
		verifyPassword(pass, dummyHash) // see dummyHash's doc comment
		return false
	}
	return verifyPassword(pass, hash)
}

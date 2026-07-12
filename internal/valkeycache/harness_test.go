package valkeycache

import (
	"testing"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/testsupport"
)

// testValkeyAddr is set by TestMain once the shared container is up, and read
// by newTestClient in every test in this package.
var testValkeyAddr string

// TestMain starts one real Valkey container for the whole test binary run (see
// testsupport.StartValkey for why a real server rather than a mock).
func TestMain(m *testing.M) {
	testsupport.RunMain(m, &testValkeyAddr)
}

// newTestClient returns a fresh Valkey client connected to the shared test
// container, and registers a cleanup that flushes the database and closes the
// connection so tests never see state left behind by another test.
func newTestClient(t *testing.T) valkey.Client {
	return testsupport.NewTestClient(t, testValkeyAddr)
}

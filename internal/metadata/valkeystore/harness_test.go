package valkeystore_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/metadata/valkeystore"
	"github.com/debproxy/debproxy/internal/testsupport"
)

// testValkeyAddr is set by TestMain once the shared container is up.
var testValkeyAddr string

// TestMain starts one real Valkey container for the whole test binary run
// (see testsupport.StartValkey for why a real server rather than a mock --
// this package in particular relies on real Lua script and SCAN semantics).
func TestMain(m *testing.M) {
	testsupport.RunMain(m, &testValkeyAddr)
}

// newStore returns a fresh Store connected to the shared test container, and
// registers a cleanup that flushes the database and closes the connection so
// tests never see state left behind by another test.
func newStore(t *testing.T) *valkeystore.Store {
	client := testsupport.NewTestClient(t, testValkeyAddr)
	return valkeystore.New(client, "")
}

package server_test

import (
	"testing"

	"github.com/debproxy/debproxy/internal/server"
	"github.com/debproxy/debproxy/internal/testsupport"
)

// TestMain starts one real Valkey container for the whole test binary run
// (see testsupport.StartValkey for why a real server rather than a mock).
func TestMain(m *testing.M) {
	testsupport.RunMain(m, &server.TestValkeyAddr)
}

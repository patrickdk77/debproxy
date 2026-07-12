package testsupport

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// ValkeyImage is the container image tests run against.
const ValkeyImage = "valkey/valkey:9"

// StartValkey launches a disposable Valkey container bound to a
// Docker-assigned free host port, waits for it to accept connections, and
// returns the "host:port" address plus a stop function that removes the
// container. An error is returned if Docker is unavailable or the image
// cannot be pulled/started. Tests that exercise real Lua scripts, TTLs, and
// Cluster hash-tag behavior use this rather than a hand-rolled fake of the
// valkey-go client, since those semantics are exactly what's under test.
func StartValkey() (addr string, stop func(), err error) {
	id, err := runDetachedContainer(ValkeyImage, []string{"-p", "127.0.0.1::6379"}, nil)
	if err != nil {
		return "", nil, err
	}
	stop = func() { removeContainer(id) }

	addr, err = containerHostPort(id, "6379/tcp")
	if err != nil {
		stop()
		return "", nil, err
	}

	if err := waitReady(addr, 30*time.Second); err != nil {
		stop()
		return "", nil, err
	}
	return addr, stop, nil
}

// NewClient opens a Valkey client to the given address.
func NewClient(addr string) (valkey.Client, error) {
	return valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
}

// RunMain is the shared TestMain body for every package that tests against a
// real Valkey container: it starts one for the whole test binary run, stores
// its address in *addr for tests to read, runs m, then stops the container.
// Like TestMain itself, it calls os.Exit and never returns.
func RunMain(m *testing.M, addr *string) {
	a, stop, err := StartValkey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "valkey tests: %v\n", err)
		fmt.Fprintln(os.Stderr, "valkey tests require Docker with access to pull "+ValkeyImage)
		os.Exit(1)
	}
	*addr = a

	code := m.Run()

	stop()
	os.Exit(code)
}

// NewTestClient returns a fresh Valkey client connected to addr, and
// registers a cleanup on t that flushes the database and closes the
// connection so tests never see state left behind by another test.
func NewTestClient(t *testing.T, addr string) valkey.Client {
	t.Helper()
	client, err := NewClient(addr)
	if err != nil {
		t.Fatalf("connecting to test valkey: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Do(context.Background(), client.B().Flushdb().Build()).Error()
		client.Close()
	})
	return client
}

func waitReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = pingOnce(addr); lastErr == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("valkey at %s did not become ready within %s: %w", addr, timeout, lastErr)
}

func pingOnce(addr string) error {
	client, err := NewClient(addr)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return client.Do(ctx, client.B().Ping().Build()).Error()
}

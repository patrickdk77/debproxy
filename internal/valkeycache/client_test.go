package valkeycache

import (
	"fmt"
	"testing"
)

func TestNewClientConnectsAndPings(t *testing.T) {
	client, err := NewClient(fmt.Sprintf("valkey://%s", testValkeyAddr))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
}

func TestNewClientBadURLReturnsError(t *testing.T) {
	if _, err := NewClient("://not-a-url"); err == nil {
		t.Fatal("expected error for malformed url, got nil")
	}
}

func TestNewClientUnreachableAddrReturnsError(t *testing.T) {
	// Port 1 is reserved and nothing should be listening there.
	if _, err := NewClient("valkey://127.0.0.1:1"); err == nil {
		t.Fatal("expected error connecting to unreachable address, got nil")
	}
}

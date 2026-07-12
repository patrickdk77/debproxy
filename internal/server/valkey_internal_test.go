package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/config"
)

func TestHandleLiveUpdatedMessageInvalidatesMatchingEntry(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)

	future := time.Now().Add(time.Hour)
	s.liveCache["debian/trixie"] = &liveEntry{expiry: future}
	s.liveCache["ubuntu/noble"] = &liveEntry{expiry: future}

	msg, err := json.Marshal(liveUpdatedMsg{OS: "debian", Codename: "trixie"})
	if err != nil {
		t.Fatal(err)
	}
	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	if !s.liveCache["debian/trixie"].expiry.IsZero() {
		t.Fatal("expected debian/trixie entry to be invalidated (zero expiry)")
	}
	if !s.liveCache["ubuntu/noble"].expiry.Equal(future) {
		t.Fatal("expected unrelated ubuntu/noble entry to be left untouched")
	}
}

func TestHandleLiveUpdatedMessageNoLocalEntryIsNoop(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)

	msg, err := json.Marshal(liveUpdatedMsg{OS: "debian", Codename: "bookworm"})
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic even though no entry exists for this os/codename.
	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: string(msg)})

	if len(s.liveCache) != 0 {
		t.Fatalf("expected no entries created, got %v", s.liveCache)
	}
}

func TestHandleLiveUpdatedMessageMalformedMessageIsIgnored(t *testing.T) {
	s := New(&config.Config{}, nil, nil, nil, nil, nil, nil, nil)
	future := time.Now().Add(time.Hour)
	s.liveCache["debian/trixie"] = &liveEntry{expiry: future}

	s.handleLiveUpdatedMessage(valkey.PubSubMessage{Message: "not json"})

	if !s.liveCache["debian/trixie"].expiry.Equal(future) {
		t.Fatal("expected entry to be untouched after a malformed message")
	}
}

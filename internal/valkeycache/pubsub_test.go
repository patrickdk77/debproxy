package valkeycache

import (
	"context"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

func TestPublishSubscribeDeliversMessage(t *testing.T) {
	v := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const channel = "events:test"
	received := make(chan valkey.PubSubMessage, 1)
	go Subscribe(ctx, v, channel, func(msg valkey.PubSubMessage) {
		received <- msg
	})

	// Give the subscription a moment to register before publishing, since a
	// message published before SUBSCRIBE completes is never delivered -- this
	// is real pub/sub fire-and-forget semantics, not a bug in Subscribe.
	time.Sleep(200 * time.Millisecond)

	pub := newTestClient(t)
	if err := Publish(ctx, pub, channel, "hello"); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case msg := <-received:
		if msg.Message != "hello" {
			t.Fatalf("got message %q, want %q", msg.Message, "hello")
		}
		if msg.Channel != channel {
			t.Fatalf("got channel %q, want %q", msg.Channel, channel)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for published message")
	}
}

func TestPublishSubscribeStopsWhenContextCanceled(t *testing.T) {
	v := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		Subscribe(ctx, v, "events:test-stop", func(valkey.PubSubMessage) {})
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Subscribe did not return after context cancellation")
	}
}

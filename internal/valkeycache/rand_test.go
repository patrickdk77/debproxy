package valkeycache

import (
	"testing"
	"time"
)

func TestRandDuration(t *testing.T) {
	if got := RandDuration(0); got != 0 {
		t.Fatalf("expected 0 for zero max, got %v", got)
	}
	if got := RandDuration(-time.Second); got != 0 {
		t.Fatalf("expected 0 for negative max, got %v", got)
	}
	max := 5 * time.Second
	for i := 0; i < 50; i++ {
		if got := RandDuration(max); got < 0 || got >= max {
			t.Fatalf("RandDuration(%v) = %v, out of range [0, %v)", max, got, max)
		}
	}
}

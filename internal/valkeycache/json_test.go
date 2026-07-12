package valkeycache

import (
	"context"
	"testing"
)

type testVal struct {
	Name  string
	Count int
}

func TestGetJSONRoundTrip(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	if err := SetJSON(ctx, c, "test:val", testVal{Name: "hello", Count: 3}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := GetJSON[testVal](ctx, c, "test:val")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok=true for an existing key")
	}
	if got.Name != "hello" || got.Count != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestGetJSONMissingKeyIsCleanMiss(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	got, ok, err := GetJSON[testVal](ctx, c, "test:missing")
	if err != nil {
		t.Fatalf("expected nil error for a missing key, got %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for a missing key")
	}
	if got != nil {
		t.Fatalf("expected nil value for a missing key, got %+v", got)
	}
}

func TestGetJSONMalformedValueIsError(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	if err := c.Do(ctx, c.B().Set().Key("test:bad").Value("not json").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	_, _, err := GetJSON[testVal](ctx, c, "test:bad")
	if err == nil {
		t.Fatal("expected an error for a malformed JSON value")
	}
}

func TestMGetJSONSparseResults(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	if err := SetJSON(ctx, c, "test:mget:a", testVal{Name: "a", Count: 1}); err != nil {
		t.Fatal(err)
	}
	if err := SetJSON(ctx, c, "test:mget:c", testVal{Name: "c", Count: 3}); err != nil {
		t.Fatal(err)
	}
	// test:mget:b deliberately left unset, to prove a missing key in the
	// middle doesn't break positional correlation for the others.

	results, ok, err := MGetJSON[testVal](ctx, c, []string{"test:mget:a", "test:mget:b", "test:mget:c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || len(ok) != 3 {
		t.Fatalf("expected 3 positional results, got %d/%d", len(results), len(ok))
	}
	if !ok[0] || results[0].Name != "a" {
		t.Fatalf("index 0: ok=%v val=%+v", ok[0], results[0])
	}
	if ok[1] {
		t.Fatalf("index 1: expected ok=false for the missing key, got %+v", results[1])
	}
	if !ok[2] || results[2].Name != "c" {
		t.Fatalf("index 2: ok=%v val=%+v", ok[2], results[2])
	}
}

func TestMGetJSONEmptyKeysReturnsNil(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	results, ok, err := MGetJSON[testVal](ctx, c, nil)
	if err != nil || results != nil || ok != nil {
		t.Fatalf("expected all nils for an empty key list, got results=%v ok=%v err=%v", results, ok, err)
	}
}

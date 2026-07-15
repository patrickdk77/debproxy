package ingest

import "testing"

func TestExistsCacheAddHasRemove(t *testing.T) {
	c := &ExistsCache{}

	if c.Has("pool/a") {
		t.Error("Has on empty cache = true, want false")
	}

	c.Add("pool/a")
	if !c.Has("pool/a") {
		t.Error("Has after Add = false, want true")
	}

	c.Remove("pool/a")
	if c.Has("pool/a") {
		t.Error("Has after Remove = true, want false")
	}
}

// TestExistsCacheRemoveUnknownPathIsNoop is the bad-data counterpart to the
// happy-path add/remove test: Remove is called by pullThrough on every
// pull-through request, most of which never had a stale (or any) cache entry
// in the first place -- it must not panic or otherwise misbehave just
// because there was nothing to clear.
func TestExistsCacheRemoveUnknownPathIsNoop(t *testing.T) {
	c := &ExistsCache{}
	c.Remove("pool/never-added")
	if c.Has("pool/never-added") {
		t.Error("Has after removing an unknown path = true, want false")
	}
}

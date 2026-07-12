package main

import (
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
	"github.com/debproxy/debproxy/internal/model"
)

func TestResolveMetadataFlushInterval(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		valkey bool
		want   time.Duration
	}{
		{"unset, valkey disabled -> 5m default", "", false, 5 * time.Minute},
		{"unset, valkey enabled -> 1h default", "", true, time.Hour},
		{"explicit 0 disables regardless of valkey", "0", false, 0},
		{"explicit 0 disables even with valkey enabled", "0", true, 0},
		{"explicit duration honored, valkey disabled", "10m", false, 10 * time.Minute},
		{"explicit duration honored, valkey enabled", "10m", true, 10 * time.Minute},
		{"invalid duration falls back to backend default", "not-a-duration", false, 5 * time.Minute},
		{"invalid duration falls back to valkey default", "not-a-duration", true, time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Schedule: config.ScheduleConfig{MetadataFlush: c.raw},
				Valkey:   config.ValkeyConfig{Enabled: c.valkey},
			}
			got := resolveMetadataFlushInterval(cfg)
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestResolveRefreshJitter(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"unset -> 5m default", "", 5 * time.Minute},
		{"explicit 0 disables jitter", "0", 0},
		{"explicit duration honored", "30s", 30 * time.Second},
		{"invalid duration falls back to default", "not-a-duration", 5 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{Schedule: config.ScheduleConfig{RefreshJitter: c.raw}}
			got := resolveRefreshJitter(cfg)
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestLayoutSeedOffsetDeterministicAndInRange(t *testing.T) {
	key := layoutKey{"debian", "trixie"}
	interval := 6 * time.Hour

	first := layoutSeedOffset(key, interval)
	for i := 0; i < 5; i++ {
		if got := layoutSeedOffset(key, interval); got != first {
			t.Fatalf("expected stable offset across calls, got %v then %v", first, got)
		}
	}
	if first < 0 || first >= interval {
		t.Fatalf("offset %v out of range [0, %v)", first, interval)
	}
}

func TestLayoutSeedOffsetDifferentLayoutsSpreadAcrossInterval(t *testing.T) {
	interval := 6 * time.Hour
	keys := []layoutKey{
		{"debian", "trixie"}, {"debian", "bookworm"}, {"debian", "experimental"},
		{"ubuntu", "noble"}, {"ubuntu", "jammy"}, {"ubuntu", "focal"}, {"ubuntu", "bionic"},
	}
	offsets := map[layoutKey]time.Duration{}
	for _, k := range keys {
		offsets[k] = layoutSeedOffset(k, interval)
	}
	seen := map[time.Duration]bool{}
	for _, off := range offsets {
		seen[off] = true
	}
	if len(seen) < len(keys)-1 {
		t.Fatalf("expected offsets to be well-distributed across %d layouts, got only %d distinct values: %v",
			len(keys), len(seen), offsets)
	}
}

func TestLayoutSeedOffsetZeroWhenIntervalNonPositive(t *testing.T) {
	key := layoutKey{"debian", "trixie"}
	if got := layoutSeedOffset(key, 0); got != 0 {
		t.Fatalf("expected 0 offset for zero interval, got %v", got)
	}
	if got := layoutSeedOffset(key, -time.Hour); got != 0 {
		t.Fatalf("expected 0 offset for negative interval, got %v", got)
	}
}

func TestLayoutUpstreamGroupsByOSCodenameInFirstSeenOrder(t *testing.T) {
	debianMain := model.UpstreamSource{Name: "debian-main", URL: "https://deb.debian.org/debian", Suite: "trixie", Component: "main"}
	debianSecurity := model.UpstreamSource{Name: "debian-security", URL: "https://deb.debian.org/debian-security", Suite: "trixie-security", Component: "main"}
	ubuntuMain := model.UpstreamSource{Name: "ubuntu-main", URL: "https://archive.ubuntu.com/ubuntu", Suite: "noble", Component: "main"}

	cfg := &config.Config{
		ResolvedLayouts: []model.Layout{
			{OS: "debian", Codename: "trixie", Component: "main", Upstreams: []model.UpstreamSource{debianMain}},
			{OS: "ubuntu", Codename: "noble", Component: "main", Upstreams: []model.UpstreamSource{ubuntuMain}},
			// A second component for the SAME (os, codename) as the first entry
			// contributes more upstreams to the SAME group, not a new one.
			{OS: "debian", Codename: "trixie", Component: "security", Upstreams: []model.UpstreamSource{debianSecurity}},
		},
	}

	keys, byKey := layoutUpstreamGroups(cfg)

	if len(keys) != 2 {
		t.Fatalf("expected 2 distinct (os, codename) groups, got %d: %v", len(keys), keys)
	}
	if keys[0] != (layoutKey{"debian", "trixie"}) || keys[1] != (layoutKey{"ubuntu", "noble"}) {
		t.Fatalf("expected first-seen order [debian/trixie, ubuntu/noble], got %v", keys)
	}

	debianUpstreams := byKey[layoutKey{"debian", "trixie"}]
	if len(debianUpstreams) != 2 {
		t.Fatalf("expected debian/trixie group to have both components' upstreams, got %v", debianUpstreams)
	}
	names := map[string]bool{}
	for _, u := range debianUpstreams {
		names[u.Name] = true
	}
	if !names["debian-main"] || !names["debian-security"] {
		t.Fatalf("expected debian-main and debian-security in debian/trixie group, got %v", debianUpstreams)
	}

	ubuntuUpstreams := byKey[layoutKey{"ubuntu", "noble"}]
	if len(ubuntuUpstreams) != 1 || ubuntuUpstreams[0].Name != "ubuntu-main" {
		t.Fatalf("expected only ubuntu-main in ubuntu/noble group, got %v", ubuntuUpstreams)
	}
}

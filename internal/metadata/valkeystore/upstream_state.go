package valkeystore

import (
	"context"
	"fmt"
	"strings"

	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

func (s *Store) UpsertUpstreamState(ctx context.Context, st model.UpstreamPackageState) error {
	if st.LastChecked.IsZero() {
		st.LastChecked = metadata.Now()
	}
	key := s.keys.UpstreamState(st.Upstream, st.PackageName, st.Arch)
	if err := valkeycache.SetJSON(ctx, s.v, key, st); err != nil {
		return fmt.Errorf("write upstream state: %w", err)
	}
	member := upstateMember(st.Upstream, st.PackageName, st.Arch)
	if err := s.v.Do(ctx, s.v.B().Sadd().Key(s.keys.BucketsUpstate()).Member(member).Build()).Error(); err != nil {
		return fmt.Errorf("register upstream state bucket: %w", err)
	}
	return nil
}

// upstateMember/splitUpstateMember encode the (upstream, package, arch)
// tuple as one SET member in BucketsUpstate, so every upstream state can be
// enumerated (e.g. for Backup) without a cluster-wide SCAN. Split on the
// first two colons only: package names never contain ":" (Debian policy),
// but this mirrors bucketMember's epoch-version caution for consistency --
// arch names in practice never contain ":" either, so a 3-way split is safe.
func upstateMember(upstream, pkg, arch string) string {
	return upstream + ":" + pkg + ":" + arch
}

func splitUpstateMember(m string) (upstream, pkg, arch string, ok bool) {
	parts := strings.SplitN(m, ":", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// ListUpstreamStates returns every upstream package state currently
// recorded, or (when upstreams is non-empty) only states belonging to one of
// those upstream names -- filtered before the MGET, not after, the same
// depth of scope push-down ListEntries/ListSourceEntries already apply via
// matchingPkgBuckets/matchingSrcBuckets. Used by Backup; not part of the
// metadata.MetadataIndex interface since no other caller needs a bulk
// listing today.
func (s *Store) ListUpstreamStates(ctx context.Context, upstreams []string) ([]model.UpstreamPackageState, error) {
	members, err := s.v.Do(ctx, s.v.B().Smembers().Key(s.keys.BucketsUpstate()).Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("list upstream state buckets: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}

	var allow map[string]bool
	if len(upstreams) > 0 {
		allow = make(map[string]bool, len(upstreams))
		for _, u := range upstreams {
			allow[u] = true
		}
	}

	stateKeys := make([]string, 0, len(members))
	for _, m := range members {
		upstream, pkg, arch, ok := splitUpstateMember(m)
		if !ok {
			continue
		}
		if allow != nil && !allow[upstream] {
			continue
		}
		stateKeys = append(stateKeys, s.keys.UpstreamState(upstream, pkg, arch))
	}
	if len(stateKeys) == 0 {
		return nil, nil
	}

	states, err := valkeycache.MGetJSONStrict[model.UpstreamPackageState](ctx, s.v, stateKeys)
	if err != nil {
		return nil, fmt.Errorf("mget upstream states: %w", err)
	}
	return states, nil
}

func (s *Store) GetUpstreamState(ctx context.Context, upstream, name, arch string) (*model.UpstreamPackageState, error) {
	key := s.keys.UpstreamState(upstream, name, arch)
	st, ok, err := valkeycache.GetJSON[model.UpstreamPackageState](ctx, s.v, key)
	if err != nil {
		return nil, fmt.Errorf("read upstream state: %w", err)
	}
	if !ok {
		return nil, nil
	}
	return st, nil
}

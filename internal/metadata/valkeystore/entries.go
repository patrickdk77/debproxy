package valkeystore

import (
	"context"
	"fmt"
	"sort"

	"github.com/valkey-io/valkey-go"

	"github.com/debproxy/debproxy/internal/debversion"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/valkeycache"
)

func (s *Store) UpsertEntry(ctx context.Context, e model.IndexEntry) error {
	if e.FirstSeen.IsZero() {
		e.FirstSeen = metadata.Now()
	}

	entryKey := s.keys.PkgEntry(e.OS, e.Codename, e.Component, e.Arch, e.Package, e.Version)
	if err := valkeycache.SetJSON(ctx, s.v, entryKey, e); err != nil {
		return fmt.Errorf("write pkg entry: %w", err)
	}

	bucketSet := s.keys.PkgBucket(e.OS, e.Codename, e.Component, e.Arch)
	member := bucketMember(e.Package, e.Version)
	if err := s.v.Do(ctx, s.v.B().Sadd().Key(bucketSet).Member(member).Build()).Error(); err != nil {
		return fmt.Errorf("index pkg bucket: %w", err)
	}

	bk := bucketKey(e.OS, e.Codename, e.Component, e.Arch)
	if err := s.v.Do(ctx, s.v.B().Sadd().Key(s.keys.BucketsIndex()).Member(bk).Build()).Error(); err != nil {
		return fmt.Errorf("register pkg bucket: %w", err)
	}

	if e.Checksums.SHA256 != "" {
		digestKey := s.keys.PkgByDigest(string(e.Checksums.SHA256))
		if err := s.v.Do(ctx, s.v.B().Set().Key(digestKey).Value(entryKey).Build()).Error(); err != nil {
			return fmt.Errorf("index pkg digest: %w", err)
		}
	}

	latestKey := s.keys.PkgLatest(e.OS, e.Codename, e.Component, e.Arch)
	if err := s.bumpLatest(ctx, latestKey, e.Package, e.Version); err != nil {
		return err
	}
	return nil
}

// bumpLatest records field=version in the latest-version hash at key if
// version is higher than what's currently recorded there (or nothing is
// recorded yet). This is an optimistic read-then-write, not an atomic
// compare-and-set: two replicas upserting different versions of the same
// package at the same instant could race and leave the lower version
// recorded as "latest" until the next write closes the gap. Debian version
// comparison (debversion.Compare) has no simple, safe Lua port, and this
// mirrors the same out-of-scope call already made for concurrent on-demand
// pull-through elsewhere in the design -- see the design doc's explicit
// decision on that race.
func (s *Store) bumpLatest(ctx context.Context, key, field, version string) error {
	current, err := s.v.Do(ctx, s.v.B().Hget().Key(key).Field(field).Build()).ToString()
	if err != nil && !valkey.IsValkeyNil(err) {
		return fmt.Errorf("read latest version: %w", err)
	}
	if current != "" && debversion.Compare(version, current) <= 0 {
		return nil
	}
	if err := s.v.Do(ctx, s.v.B().Hset().Key(key).FieldValue().FieldValue(field, version).Build()).Error(); err != nil {
		return fmt.Errorf("write latest version: %w", err)
	}
	return nil
}

// RemoveEntry deletes the entry matching e's identity (OS/Codename/Component/
// Arch/Package/Version); other fields are ignored for matching. A no-op if no
// matching entry exists. Does not touch PkgLatest -- like bumpLatest itself,
// that hash is already documented best-effort (see its own doc comment), and
// recomputing it here would mean scanning the whole bucket on every removal
// for a value nothing else in this codebase treats as authoritative; a
// consumer wanting a guaranteed-live "latest" version already has to call
// FindEntry and read the entry back (see FindEntry finding a now-empty
// getEntry result as a real "not found").
func (s *Store) RemoveEntry(ctx context.Context, e model.IndexEntry) error {
	entryKey := s.keys.PkgEntry(e.OS, e.Codename, e.Component, e.Arch, e.Package, e.Version)
	if err := s.v.Do(ctx, s.v.B().Del().Key(entryKey).Build()).Error(); err != nil {
		return fmt.Errorf("delete pkg entry: %w", err)
	}

	bucketSet := s.keys.PkgBucket(e.OS, e.Codename, e.Component, e.Arch)
	member := bucketMember(e.Package, e.Version)
	if err := s.v.Do(ctx, s.v.B().Srem().Key(bucketSet).Member(member).Build()).Error(); err != nil {
		return fmt.Errorf("unindex pkg bucket: %w", err)
	}

	if e.Checksums.SHA256 != "" {
		digestKey := s.keys.PkgByDigest(string(e.Checksums.SHA256))
		// Only clear the pointer if it still points at the entry being
		// removed -- a different, still-live entry may have since claimed
		// the same digest (two placements of identical content).
		current, err := s.v.Do(ctx, s.v.B().Get().Key(digestKey).Build()).ToString()
		if err != nil && !valkey.IsValkeyNil(err) {
			return fmt.Errorf("read pkg digest: %w", err)
		}
		if current == entryKey {
			if err := s.v.Do(ctx, s.v.B().Del().Key(digestKey).Build()).Error(); err != nil {
				return fmt.Errorf("delete pkg digest: %w", err)
			}
		}
	}
	return nil
}

func (s *Store) matchingPkgBuckets(ctx context.Context, sel model.Selector) ([]pkgBucket, error) {
	all, err := s.v.Do(ctx, s.v.B().Smembers().Key(s.keys.BucketsIndex()).Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("list pkg buckets: %w", err)
	}
	var out []pkgBucket
	for _, k := range all {
		osName, codename, component, arch, ok := splitBucketKey(k)
		if !ok || !pkgBucketMatches(sel, osName, codename, component, arch) {
			continue
		}
		out = append(out, pkgBucket{osName, codename, component, arch})
	}
	return out, nil
}

func (s *Store) ListEntries(ctx context.Context, sel model.Selector) ([]model.IndexEntry, error) {
	buckets, err := s.matchingPkgBuckets(ctx, sel)
	if err != nil {
		return nil, err
	}

	var out []model.IndexEntry
	for _, b := range buckets {
		// ScanSetMembers (SSCAN), not SMEMBERS: some buckets (e.g. Ubuntu's
		// "universe" component) run to tens of thousands of members, and a
		// single SMEMBERS reply for one of those is itself sizable.
		members, err := valkeycache.ScanSetMembers(ctx, s.v, s.keys.PkgBucket(b.os, b.codename, b.component, b.arch))
		if err != nil {
			return nil, fmt.Errorf("list pkg bucket: %w", err)
		}
		if len(members) == 0 {
			continue
		}
		entryKeys := make([]string, 0, len(members))
		for _, m := range members {
			pkg, ver, ok := splitBucketMember(m)
			if !ok {
				continue
			}
			entryKeys = append(entryKeys, s.keys.PkgEntry(b.os, b.codename, b.component, b.arch, pkg, ver))
		}
		if len(entryKeys) == 0 {
			continue
		}
		// MGetJSONStrictBatched: chunked so no single MGET reply is ever
		// unbounded by the bucket's size (the same tens-of-thousands-of-
		// members buckets noted above would otherwise produce one
		// multi-hundred-MB reply). A missing entry (vanished between the
		// SSCAN and its MGET, e.g. concurrent GC) is skipped, but a value
		// that exists and fails to decode fails the whole list -- that's
		// real corruption, not a race.
		entries, err := valkeycache.MGetJSONStrictBatched[model.IndexEntry](ctx, s.v, entryKeys)
		if err != nil {
			return nil, fmt.Errorf("mget pkg entries: %w", err)
		}
		out = append(out, entries...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return debversion.Compare(out[i].Version, out[j].Version) < 0
	})
	return out, nil
}

func (s *Store) EntryByDigest(ctx context.Context, digest model.Digest) (*model.IndexEntry, error) {
	entryKey, err := s.v.Do(ctx, s.v.B().Get().Key(s.keys.PkgByDigest(string(digest))).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup digest: %w", err)
	}
	return s.getEntry(ctx, entryKey)
}

func (s *Store) getEntry(ctx context.Context, entryKey string) (*model.IndexEntry, error) {
	e, ok, err := valkeycache.GetJSON[model.IndexEntry](ctx, s.v, entryKey)
	if err != nil {
		return nil, fmt.Errorf("read pkg entry: %w", err)
	}
	if !ok {
		return nil, nil
	}
	return e, nil
}

func (s *Store) FindEntry(ctx context.Context, sel model.Selector, pkg, version string) (*model.IndexEntry, error) {
	buckets, err := s.matchingPkgBuckets(ctx, sel)
	if err != nil {
		return nil, err
	}

	if version != "" {
		for _, b := range buckets {
			entryKey := s.keys.PkgEntry(b.os, b.codename, b.component, b.arch, pkg, version)
			e, err := s.getEntry(ctx, entryKey)
			if err != nil {
				return nil, err
			}
			if e != nil {
				return e, nil
			}
		}
		return nil, nil
	}

	// No version given: find the highest version for pkg across all matching
	// buckets via each bucket's latest-version hash, then read that one entry.
	var bestBucket pkgBucket
	var bestVersion string
	for _, b := range buckets {
		v, err := s.v.Do(ctx, s.v.B().Hget().Key(s.keys.PkgLatest(b.os, b.codename, b.component, b.arch)).Field(pkg).Build()).ToString()
		if err != nil {
			if valkey.IsValkeyNil(err) {
				continue
			}
			return nil, fmt.Errorf("read latest version: %w", err)
		}
		if bestVersion == "" || debversion.Compare(v, bestVersion) > 0 {
			bestVersion = v
			bestBucket = b
		}
	}
	if bestVersion == "" {
		return nil, nil
	}
	return s.getEntry(ctx, s.keys.PkgEntry(bestBucket.os, bestBucket.codename, bestBucket.component, bestBucket.arch, pkg, bestVersion))
}

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

func (s *Store) UpsertSourceEntry(ctx context.Context, e model.SourceEntry) error {
	if e.FirstSeen.IsZero() {
		e.FirstSeen = metadata.Now()
	}

	// FilesDownloaded and FirstSeen are sticky once set, matching
	// deb822store's UpsertSourceEntry: an update that hasn't downloaded files
	// itself must not clear a prior download, and the original first-seen
	// time must survive later metadata-only updates.
	entryKey := s.keys.SrcEntry(e.OS, e.Codename, e.Component, e.Package, e.Version)
	if existing, err := s.getSourceEntry(ctx, entryKey); err != nil {
		return err
	} else if existing != nil {
		e.FilesDownloaded = e.FilesDownloaded || existing.FilesDownloaded
		e.FirstSeen = existing.FirstSeen
	}

	if err := valkeycache.SetJSON(ctx, s.v, entryKey, e); err != nil {
		return fmt.Errorf("write src entry: %w", err)
	}

	bucketSet := s.keys.SrcBucket(e.OS, e.Codename, e.Component)
	member := bucketMember(e.Package, e.Version)
	if err := s.v.Do(ctx, s.v.B().Sadd().Key(bucketSet).Member(member).Build()).Error(); err != nil {
		return fmt.Errorf("index src bucket: %w", err)
	}

	bk := srcBucketKeyStr(e.OS, e.Codename, e.Component)
	if err := s.v.Do(ctx, s.v.B().Sadd().Key(s.keys.BucketsSrc()).Member(bk).Build()).Error(); err != nil {
		return fmt.Errorf("register src bucket: %w", err)
	}

	latestKey := s.keys.SrcLatest(e.OS, e.Codename, e.Component)
	if err := s.bumpLatest(ctx, latestKey, e.Package, e.Version); err != nil {
		return err
	}
	return nil
}

func (s *Store) matchingSrcBuckets(ctx context.Context, sel model.Selector) ([]srcBucket, error) {
	all, err := s.v.Do(ctx, s.v.B().Smembers().Key(s.keys.BucketsSrc()).Build()).AsStrSlice()
	if err != nil {
		return nil, fmt.Errorf("list src buckets: %w", err)
	}
	var out []srcBucket
	for _, k := range all {
		osName, codename, component, ok := splitSrcBucketKey(k)
		if !ok || !srcBucketMatches(sel, osName, codename, component) {
			continue
		}
		out = append(out, srcBucket{osName, codename, component})
	}
	return out, nil
}

func (s *Store) ListSourceEntries(ctx context.Context, sel model.Selector) ([]model.SourceEntry, error) {
	buckets, err := s.matchingSrcBuckets(ctx, sel)
	if err != nil {
		return nil, err
	}

	var out []model.SourceEntry
	for _, b := range buckets {
		members, err := s.v.Do(ctx, s.v.B().Smembers().Key(s.keys.SrcBucket(b.os, b.codename, b.component)).Build()).AsStrSlice()
		if err != nil {
			return nil, fmt.Errorf("list src bucket: %w", err)
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
			entryKeys = append(entryKeys, s.keys.SrcEntry(b.os, b.codename, b.component, pkg, ver))
		}
		if len(entryKeys) == 0 {
			continue
		}
		entries, err := valkeycache.MGetJSONStrict[model.SourceEntry](ctx, s.v, entryKeys)
		if err != nil {
			return nil, fmt.Errorf("mget src entries: %w", err)
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

func (s *Store) getSourceEntry(ctx context.Context, entryKey string) (*model.SourceEntry, error) {
	e, ok, err := valkeycache.GetJSON[model.SourceEntry](ctx, s.v, entryKey)
	if err != nil {
		return nil, fmt.Errorf("read src entry: %w", err)
	}
	if !ok {
		return nil, nil
	}
	return e, nil
}

func (s *Store) FindSourceEntry(ctx context.Context, sel model.Selector, pkg, version string) (*model.SourceEntry, error) {
	buckets, err := s.matchingSrcBuckets(ctx, sel)
	if err != nil {
		return nil, err
	}

	if version != "" {
		for _, b := range buckets {
			e, err := s.getSourceEntry(ctx, s.keys.SrcEntry(b.os, b.codename, b.component, pkg, version))
			if err != nil {
				return nil, err
			}
			if e != nil {
				return e, nil
			}
		}
		return nil, nil
	}

	var bestBucket srcBucket
	var bestVersion string
	for _, b := range buckets {
		v, err := s.v.Do(ctx, s.v.B().Hget().Key(s.keys.SrcLatest(b.os, b.codename, b.component)).Field(pkg).Build()).ToString()
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
	return s.getSourceEntry(ctx, s.keys.SrcEntry(bestBucket.os, bestBucket.codename, bestBucket.component, pkg, bestVersion))
}

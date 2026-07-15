// Package ingest downloads, verifies, stores, and indexes upstream packages.
package ingest

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/metrics"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/webhook"
)

// ExistsCache is a persistent in-memory set of pool paths known to exist in
// storage. Under normal operation pool files are never deleted, so a positive
// hit remains valid indefinitely and S3/filesystem Exists checks can be
// skipped on subsequent Cache calls for the same path. That assumption can be
// violated out-of-band (a GC bug, a manual purge) -- see Remove, which lets a
// caller that has independently proven a path no longer exists correct a
// stale positive rather than have Cache trust it forever.
type ExistsCache struct {
	m sync.Map
}

func (c *ExistsCache) Has(path string) bool {
	_, ok := c.m.Load(path)
	return ok
}

func (c *ExistsCache) Add(path string) {
	c.m.Store(path, struct{}{})
}

// Remove clears any positive entry for path, forcing the next Cache call for
// it to re-verify against real storage instead of trusting a stale hit.
func (c *ExistsCache) Remove(path string) {
	c.m.Delete(path)
}

// Ingestor caches packages into the pool and records index entries.
type Ingestor struct {
	store    storage.Storage
	index    metadata.MetadataIndex
	client   *http.Client
	notifier *webhook.Notifier
	exists   *ExistsCache // optional; nil disables caching
}

// New returns an Ingestor. notifier and exists may be nil.
func New(store storage.Storage, index metadata.MetadataIndex, client *http.Client, notifier *webhook.Notifier, exists *ExistsCache) *Ingestor {
	return &Ingestor{store: store, index: index, client: client, notifier: notifier, exists: exists}
}

// Cache ensures the package's .deb is in the pool (downloading and verifying if
// needed) and records its index entry. It is idempotent. notify controls
// whether a freshly-downloaded package fires a webhook event: callers
// downloading a whole dependency closure (Syncer.Prime, and pull-through) want
// every real download notified, but Syncer.runUpdate's auto_update pass wants
// only the top-level package whose newer version triggered the update to
// notify -- a dependency pulled in solely to satisfy that package's
// requirements isn't itself a separate update worth notifying about.
func (in *Ingestor) Cache(ctx context.Context, osName, codename string, p avail.Pkg, notify bool) error {
	if in.exists == nil || !in.exists.Has(p.PoolPath) {
		exists, err := in.store.Exists(ctx, p.PoolPath)
		if err != nil {
			return err
		}
		if !exists {
			slog.Debug("downloading package", "package", p.Name, "version", p.Version, "upstream", p.Upstream.Name)
			f := upstream.NewFetcher(p.Upstream, in.client)
			data, err := f.DownloadDeb(ctx, p.Filename, p.SHA256)
			if err != nil {
				return err
			}
			if err := in.store.PutFile(ctx, p.PoolPath, bytes.NewReader(data), int64(len(data))); err != nil {
				return err
			}
			slog.Info("cached package", "package", p.Name, "version", p.Version, "upstream", p.Upstream.Name, "path", p.PoolPath)
			if p.Upstream.AutoUpdate {
				metrics.AutoUpdateFilesTotal.WithLabelValues(osName, codename, p.Upstream.Name).Inc()
			}
			if notify {
				in.notifier.Fire(webhook.Event{
					Package:   p.Name,
					Version:   p.Version,
					Arch:      p.Arch,
					OS:        osName,
					Codename:  codename,
					Component: p.Component,
					Section:   p.Section,
					Upstream:  p.Upstream.Name,
					PoolPath:  p.PoolPath,
					Size:      p.Size,
				})
			}
		}
		if in.exists != nil {
			in.exists.Add(p.PoolPath)
		}
	}

	entry := model.IndexEntry{
		OS:             osName,
		Codename:       codename,
		Component:      p.Component,
		Arch:           p.Arch,
		Package:        p.Name,
		Version:        p.Version,
		Upstream:       p.Upstream.Name,
		FromAutoUpdate: p.Upstream.AutoUpdate,
		PoolPath:       p.PoolPath,
		Checksums: model.Checksums{
			SHA256: model.Digest(p.SHA256),
			SHA512: model.Digest(p.SHA512),
		},
		Size:      p.Size,
		Control:   p.StanzaStr,
		FirstSeen: metadata.Now(),
	}
	return in.index.UpsertEntry(ctx, entry)
}

// CacheSourceFile downloads one source package file from the upstream and
// stores it under src/. It is idempotent: if the file is already present it
// returns immediately without verifying the content.
func (in *Ingestor) CacheSourceFile(ctx context.Context, entry model.SourceEntry, us model.UpstreamSource, filename string) error {
	var srcFile *model.SourceFile
	for i := range entry.Files {
		if entry.Files[i].Filename == filename {
			srcFile = &entry.Files[i]
			break
		}
	}
	if srcFile == nil {
		return fmt.Errorf("file %s not listed in source entry %s %s", filename, entry.Package, entry.Version)
	}

	filePath := model.SourceFilePath(entry.OS, entry.Codename, entry.Upstream, entry.Component, entry.Package, filename)

	if in.exists != nil && in.exists.Has(filePath) {
		return nil
	}
	exists, err := in.store.Exists(ctx, filePath)
	if err != nil {
		return err
	}
	if exists {
		if in.exists != nil {
			in.exists.Add(filePath)
		}
		return nil
	}

	slog.Debug("downloading source file", "package", entry.Package, "version", entry.Version, "file", filename, "upstream", entry.Upstream)
	f := upstream.NewFetcher(us, in.client)
	data, err := f.DownloadSourceFile(ctx, entry.UpstreamDir, filename, string(srcFile.SHA256))
	if err != nil {
		return err
	}
	if err := in.store.PutFile(ctx, filePath, bytes.NewReader(data), int64(len(data))); err != nil {
		return err
	}
	slog.Info("cached source file", "package", entry.Package, "version", entry.Version, "file", filename, "upstream", entry.Upstream)
	if in.exists != nil {
		in.exists.Add(filePath)
	}
	if us.AutoUpdate {
		metrics.AutoUpdateSourceFilesTotal.WithLabelValues(entry.OS, entry.Codename, entry.Upstream).Inc()
	}
	return nil
}

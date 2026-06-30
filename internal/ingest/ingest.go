// Package ingest downloads, verifies, stores, and indexes upstream packages.
package ingest

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"

	"github.com/debproxy/debproxy/internal/avail"
	"github.com/debproxy/debproxy/internal/metadata"
	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/storage"
	"github.com/debproxy/debproxy/internal/upstream"
	"github.com/debproxy/debproxy/internal/webhook"
)

// Ingestor caches packages into the pool and records index entries.
type Ingestor struct {
	store    storage.Storage
	index    metadata.MetadataIndex
	client   *http.Client
	notifier *webhook.Notifier
}

// New returns an Ingestor. notifier may be nil.
func New(store storage.Storage, index metadata.MetadataIndex, client *http.Client, notifier *webhook.Notifier) *Ingestor {
	return &Ingestor{store: store, index: index, client: client, notifier: notifier}
}

// Cache ensures the package's .deb is in the pool (downloading and verifying if
// needed) and records its index entry. It is idempotent.
func (in *Ingestor) Cache(ctx context.Context, osName, codename string, p avail.Pkg) error {
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

// Package webhook fires HTTP POST notifications when new packages are ingested.
package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"
)

// Def is one webhook endpoint, loaded from config.
type Def struct {
	URL         string            `yaml:"url"`
	ContentType string            `yaml:"content_type"`
	// Headers are sent with every request. Values starting with "$" are
	// expanded from the environment at startup (e.g. "$GOTIFY_TOKEN").
	Headers   map[string]string `yaml:"headers"`
	// Body is a Go text/template rendered for each event. Available fields:
	// .Package .Version .Arch .OS .Codename .Component .Section .Upstream .PoolPath .Size
	Body      string   `yaml:"body"`
	// Upstreams restricts firing to the named upstreams. Empty fires for all.
	Upstreams []string `yaml:"upstreams"`
}

// Event describes a newly downloaded .deb file.
type Event struct {
	Package   string
	Version   string
	Arch      string
	OS        string
	Codename  string
	Component string
	Section   string
	Upstream  string
	PoolPath  string
	Size      int64
}

type compiled struct {
	url         string
	contentType string
	headers     map[string]string
	tmpl        *template.Template
	hasBody     bool            // false → GET with no body; true → POST with rendered body
	upstreams   map[string]bool // empty = all
}

// Notifier fires HTTP webhooks when new packages are downloaded.
// A nil Notifier is safe to use — all calls are no-ops.
type Notifier struct {
	hooks  []compiled
	client *http.Client
}

// New compiles defs into a Notifier ready to fire. A nil client creates a
// dedicated one with a 15-second timeout.
func New(defs []Def, client *http.Client) (*Notifier, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	n := &Notifier{client: client}
	for i, d := range defs {
		if d.URL == "" {
			return nil, fmt.Errorf("webhook[%d]: url is required", i)
		}
		tmpl, err := template.New("").Parse(d.Body)
		if err != nil {
			return nil, fmt.Errorf("webhook[%d] body template: %w", i, err)
		}
		ct := d.ContentType
		if ct == "" {
			ct = "application/json"
		}
		upstreams := make(map[string]bool, len(d.Upstreams))
		for _, u := range d.Upstreams {
			upstreams[u] = true
		}
		headers := make(map[string]string, len(d.Headers))
		for k, v := range d.Headers {
			if strings.HasPrefix(v, "$") {
				v = os.Getenv(strings.TrimPrefix(v, "$"))
			}
			headers[k] = v
		}
		n.hooks = append(n.hooks, compiled{
			url:         d.URL,
			contentType: ct,
			headers:     headers,
			tmpl:        tmpl,
			hasBody:     d.Body != "",
			upstreams:   upstreams,
		})
	}
	return n, nil
}

// Fire dispatches all matching webhooks for ev. Each hook fires in its own
// goroutine with a 15-second timeout; errors are logged and do not block the caller.
func (n *Notifier) Fire(ev Event) {
	if n == nil || len(n.hooks) == 0 {
		return
	}
	for _, h := range n.hooks {
		if len(h.upstreams) > 0 && !h.upstreams[ev.Upstream] {
			continue
		}
		go func(h compiled) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := send(ctx, n.client, h, ev); err != nil {
				slog.Warn("webhook", "url", h.url, "package", ev.Package, "err", err)
			}
		}(h)
	}
}

func send(ctx context.Context, client *http.Client, h compiled, ev Event) error {
	var req *http.Request
	var err error
	if h.hasBody {
		var buf bytes.Buffer
		if err = h.tmpl.Execute(&buf, ev); err != nil {
			return fmt.Errorf("render template: %w", err)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, h.url, &buf)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", h.contentType)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
		if err != nil {
			return err
		}
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

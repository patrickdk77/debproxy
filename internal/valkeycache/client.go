// Package valkeycache provides the shared Valkey client plus the primitives
// (distributed lock, pub/sub, key naming) that let multiple debproxy
// replicas coordinate upstream fetches and share live-serving artifacts
// through a common Valkey/Redis deployment. See the design doc for the full
// key schema and rationale.
package valkeycache

import (
	"context"
	"fmt"
	"net/url"

	"github.com/valkey-io/valkey-go"
)

// NewClient parses url and connects, verifying connectivity with a PING
// before returning. url accepts the full grammar of valkey.ParseURL:
// redis://, rediss://, valkey://, or valkeys:// (the "s" schemes enable
// TLS), repeated "?addr=host:port" query params for additional Cluster
// nodes (auto-detected at connect time), and "?master_set=name" for
// Sentinel. All of that is handled by the driver; debproxy does not
// implement any of its own topology or TLS logic.
func NewClient(rawURL string) (valkey.Client, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw URL string: %w", err)
	}
	queryParams := parsedURL.Query()
	sentinelUser := queryParams.Get("sentinel_username")
	sentinelPass := queryParams.Get("sentinel_password")

	queryParams.Del("sentinel_username")
	queryParams.Del("sentinel_password")

	parsedURL.RawQuery = queryParams.Encode()
	opt, err := valkey.ParseURL(parsedURL.String())
	if err != nil {
		return nil, fmt.Errorf("parse valkey url: %w", err)
	}
	if sentinelUser != "" {
		opt.Sentinel.Username = sentinelUser
	}
	if sentinelPass != "" {
		opt.Sentinel.Password = sentinelPass
	}

	client, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("create valkey client: %w", err)
	}
	if err := client.Do(context.Background(), client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("connect to valkey: %w", err)
	}
	return client, nil
}

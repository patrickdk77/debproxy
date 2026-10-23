// Package valkeycache provides the shared Valkey client plus the primitives
// (distributed lock, pub/sub, key naming) that let multiple debproxy
// replicas coordinate upstream fetches and share live-serving artifacts
// through a common Valkey/Redis deployment. See the design doc for the full
// key schema and rationale.
package valkeycache

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

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
		// url.Error carries the full input, credentials included, so it
		// must not be wrapped into something that gets logged.
		return nil, fmt.Errorf("failed to parse valkey url (%s): %w", redactURL(rawURL), unwrapURLErr(err))
	}
	queryParams := parsedURL.Query()
	sentinelUser := queryParams.Get("sentinel_username")
	sentinelPass := queryParams.Get("sentinel_password")

	queryParams.Del("sentinel_username")
	queryParams.Del("sentinel_password")

	parsedURL.RawQuery = queryParams.Encode()
	opt, err := valkey.ParseURL(parsedURL.String())
	if err != nil {
		return nil, fmt.Errorf("parse valkey url (%s): %w", redactURL(rawURL), unwrapURLErr(err))
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

// redactURL returns rawURL with any userinfo password replaced, for use in
// errors and logs. It works on the string rather than a parsed URL because
// the common reason to need it is that parsing failed.
func redactURL(rawURL string) string {
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return rawURL
	}
	rest := rawURL[schemeEnd+3:]
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return rawURL
	}
	userinfo := rest[:at]
	if colon := strings.Index(userinfo, ":"); colon >= 0 {
		userinfo = userinfo[:colon] + ":xxxxx"
	}
	return rawURL[:schemeEnd+3] + userinfo + rest[at:]
}

// unwrapURLErr strips the *url.Error wrapper, whose Error() prints the
// whole URL, leaving only the underlying reason.
func unwrapURLErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

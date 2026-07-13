package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// discoveryDoc is the subset of an OIDC provider's
// .well-known/openid-configuration document this package uses.
type discoveryDoc struct {
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// fetchDiscovery fetches and parses issuer's OIDC discovery document.
func fetchDiscovery(ctx context.Context, client *http.Client, issuer string) (*discoveryDoc, error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document: unexpected status %d", resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document has no jwks_uri")
	}
	return &doc, nil
}

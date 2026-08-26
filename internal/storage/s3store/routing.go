package s3store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Pool routing exists because of how apt resolves a package's location.
//
// A Packages stanza's Filename is relative to the sources.list URIs
// base, so apt asks for <base>/<Filename>. debproxy publishes a
// snapshot's metadata under "<snapshotID>/<os>/dists/..." but keeps a
// single shared pool at "pool/" so snapshots do not each duplicate
// every .deb. Serving through debproxy that mismatch is invisible --
// handleSnapshot strips the snapshot prefix and reads the shared pool
// key. Served straight off the bucket there is nothing to do the
// stripping, so every .deb 404s while the metadata resolves fine.
//
// An S3 website routing rule closes the gap without duplicating a
// single byte: it rewrites the "<snapshotID>/<os>/pool/" prefix back to
// "pool/". The catch is that S3 conditions match a literal prefix --
// no wildcards, no regex, and no matching a varying middle segment
// (see the Condition API reference) -- and the snapshot ID is the
// leading segment. So every published base needs its own rule, which
// is why these are reconciled from the live snapshot list rather than
// configured by hand.
const (
	// poolPrefix is the shared pool's own key prefix, and the target
	// every managed rule rewrites to.
	poolPrefix = "pool/"

	// maxRoutingRules is the S3 limit on routing rules per bucket
	// website configuration. Exceeding it is rejected outright, so
	// the reconciler trims and says what it dropped rather than
	// letting the whole update fail.
	maxRoutingRules = 50
)

// SyncPoolRoutes reconciles the bucket's website routing rules so that
// each published base in bases has a rule rewriting its pool prefix to
// the shared pool.
//
// bases are publish bases without a trailing slash, e.g. "current/debian"
// or "2026-08-11/debian". The full desired rule set is computed and
// written every time rather than diffed, so a partially applied or
// hand-edited configuration heals on the next run and a snapshot that
// was pruned loses its rule without needing a separate delete path.
//
// Rules the reconciler did not create are preserved untouched: it owns
// exactly those rewriting a "<something>/pool/" prefix to poolPrefix.
func (s *Store) SyncPoolRoutes(ctx context.Context, bases []string) error {
	current, err := s.getWebsiteConfig(ctx)
	if err != nil {
		return err
	}
	if current == nil {
		// Website hosting is off, so routing rules would have no
		// effect. Turning it on here would change how the whole
		// bucket serves, which is not this function's call to make.
		slog.Warn("s3 website hosting is not enabled on the bucket; " +
			"skipping pool routing rules (direct-from-bucket " +
			"package downloads will 404)")
		return nil
	}

	foreign, mine := partitionRules(current.RoutingRules)
	desired, dropped := desiredRules(bases, len(foreign))
	if dropped > 0 {
		slog.Warn("s3 routing rule limit reached; some published "+
			"bases will not resolve pool files directly from the "+
			"bucket",
			"limit", maxRoutingRules,
			"foreign_rules", len(foreign),
			"bases", len(bases),
			"dropped", dropped)
	}
	if sameRules(mine, desired) {
		return nil
	}

	current.RoutingRules = append(append([]types.RoutingRule{},
		foreign...), desired...)
	if _, err := s.client.PutBucketWebsite(ctx,
		&s3.PutBucketWebsiteInput{
			Bucket:               aws.String(s.bucket),
			WebsiteConfiguration: current,
		}); err != nil {
		return fmt.Errorf("put bucket website config: %w", err)
	}
	slog.Info("synced s3 pool routing rules",
		"managed", len(desired), "preserved", len(foreign))
	return nil
}

// getWebsiteConfig returns the bucket's current website configuration,
// or nil when website hosting is not enabled.
func (s *Store) getWebsiteConfig(ctx context.Context) (
	*types.WebsiteConfiguration, error) {

	out, err := s.client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
		Bucket: aws.String(s.bucket),
	})
	if err != nil {
		if isNoSuchWebsiteConfiguration(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get bucket website config: %w", err)
	}
	return &types.WebsiteConfiguration{
		ErrorDocument:         out.ErrorDocument,
		IndexDocument:         out.IndexDocument,
		RedirectAllRequestsTo: out.RedirectAllRequestsTo,
		RoutingRules:          out.RoutingRules,
	}, nil
}

func isNoSuchWebsiteConfiguration(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "NoSuchWebsiteConfiguration"
	}
	return false
}

// partitionRules splits existing rules into those the reconciler does
// not own (returned first, always preserved) and those it does.
func partitionRules(rules []types.RoutingRule) (
	foreign, mine []types.RoutingRule) {

	for _, r := range rules {
		if isManagedRule(r) {
			mine = append(mine, r)
			continue
		}
		foreign = append(foreign, r)
	}
	return foreign, mine
}

// isManagedRule reports whether a rule looks like one SyncPoolRoutes
// created: a pool-prefix rewrite pointing at the shared pool. Rules are
// unnamed in the S3 API, so this shape is the only ownership marker
// available -- which is also why it is deliberately narrow.
func isManagedRule(r types.RoutingRule) bool {
	if r.Condition == nil || r.Condition.KeyPrefixEquals == nil {
		return false
	}
	if r.Redirect == nil || r.Redirect.ReplaceKeyPrefixWith == nil {
		return false
	}
	if aws.ToString(r.Redirect.ReplaceKeyPrefixWith) != poolPrefix {
		return false
	}
	key := aws.ToString(r.Condition.KeyPrefixEquals)
	return strings.HasSuffix(key, "/"+poolPrefix)
}

// desiredRules builds the managed rule set for bases, trimmed to fit
// under maxRoutingRules alongside foreignCount rules it must not
// disturb. It reports how many bases were dropped.
//
// "current" bases are kept first: they are what live clients point at,
// and a dated snapshot losing direct-from-bucket access degrades far
// less than the current suite losing it. Remaining bases are kept in
// reverse lexical order, which for date-stamped snapshot IDs keeps the
// newest.
func desiredRules(bases []string, foreignCount int) (
	[]types.RoutingRule, int) {

	ordered := orderBases(bases)

	budget := maxRoutingRules - foreignCount
	if budget < 0 {
		budget = 0
	}
	dropped := 0
	if len(ordered) > budget {
		dropped = len(ordered) - budget
		ordered = ordered[:budget]
	}

	rules := make([]types.RoutingRule, 0, len(ordered))
	for _, base := range ordered {
		prefix := strings.Trim(base, "/") + "/" + poolPrefix
		rules = append(rules, types.RoutingRule{
			Condition: &types.Condition{
				KeyPrefixEquals: aws.String(prefix),
			},
			Redirect: &types.Redirect{
				ReplaceKeyPrefixWith: aws.String(poolPrefix),
			},
		})
	}
	return rules, dropped
}

// orderBases deduplicates and orders bases: "current/..." first, then
// the rest newest-first by reverse lexical order.
func orderBases(bases []string) []string {
	seen := map[string]bool{}
	var currents, rest []string
	for _, b := range bases {
		b = strings.Trim(b, "/")
		if b == "" || seen[b] {
			continue
		}
		seen[b] = true
		if strings.HasPrefix(b, "current/") || b == "current" {
			currents = append(currents, b)
			continue
		}
		rest = append(rest, b)
	}
	sort.Strings(currents)
	sort.Sort(sort.Reverse(sort.StringSlice(rest)))
	return append(currents, rest...)
}

// sameRules reports whether two managed rule sets are equivalent, so an
// unchanged configuration is not rewritten on every publish.
func sameRules(a, b []types.RoutingRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if aws.ToString(a[i].Condition.KeyPrefixEquals) !=
			aws.ToString(b[i].Condition.KeyPrefixEquals) {
			return false
		}
		if aws.ToString(a[i].Redirect.ReplaceKeyPrefixWith) !=
			aws.ToString(b[i].Redirect.ReplaceKeyPrefixWith) {
			return false
		}
	}
	return true
}

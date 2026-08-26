package s3store

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// noWebsiteErr mimics the API error S3 returns for a bucket with no
// website configuration.
type noWebsiteErr struct{ smithy.APIError }

func (noWebsiteErr) ErrorCode() string {
	return "NoSuchWebsiteConfiguration"
}
func (noWebsiteErr) Error() string {
	return "NoSuchWebsiteConfiguration"
}

func managedRule(prefix string) types.RoutingRule {
	return types.RoutingRule{
		Condition: &types.Condition{
			KeyPrefixEquals: aws.String(prefix),
		},
		Redirect: &types.Redirect{
			ReplaceKeyPrefixWith: aws.String(poolPrefix),
		},
	}
}

// routingFake wires a fakeS3 with a website config and records writes.
type routingFake struct {
	*fakeS3
	written []*s3.PutBucketWebsiteInput
}

func newRoutingFake(cfg *s3.GetBucketWebsiteOutput,
	getErr error) *routingFake {

	rf := &routingFake{fakeS3: &fakeS3{}}
	rf.fakeS3.getWebsite = func() (*s3.GetBucketWebsiteOutput, error) {
		if getErr != nil {
			return nil, getErr
		}
		return cfg, nil
	}
	rf.fakeS3.putWebsite = func(in *s3.PutBucketWebsiteInput) (
		*s3.PutBucketWebsiteOutput, error) {
		rf.written = append(rf.written, in)
		return &s3.PutBucketWebsiteOutput{}, nil
	}
	return rf
}

func (rf *routingFake) store() *Store {
	return &Store{client: rf.fakeS3, bucket: "b"}
}

func prefixes(in *s3.PutBucketWebsiteInput) []string {
	var out []string
	for _, r := range in.WebsiteConfiguration.RoutingRules {
		out = append(out,
			aws.ToString(r.Condition.KeyPrefixEquals))
	}
	return out
}

func TestSyncPoolRoutesCreatesRuleForEachBase(t *testing.T) {
	rf := newRoutingFake(&s3.GetBucketWebsiteOutput{
		IndexDocument: &types.IndexDocument{
			Suffix: aws.String("index.html"),
		},
	}, nil)

	err := rf.store().SyncPoolRoutes(context.Background(),
		[]string{"current/debian", "2026-08-11/debian"})
	if err != nil {
		t.Fatalf("SyncPoolRoutes: %v", err)
	}
	if len(rf.written) != 1 {
		t.Fatalf("wrote %d configs, want 1", len(rf.written))
	}
	got := prefixes(rf.written[0])
	want := []string{
		"current/debian/pool/",
		"2026-08-11/debian/pool/",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("prefixes %v, want %v", got, want)
	}
	// The rest of the website config must survive untouched.
	if rf.written[0].WebsiteConfiguration.IndexDocument == nil {
		t.Error("IndexDocument was dropped from the config")
	}
}

// TestSyncPoolRoutesDropsPrunedSnapshots is the delete half: a base
// that no longer exists must lose its rule, which is what makes
// reconciling the whole set sufficient without a delete path.
func TestSyncPoolRoutesDropsPrunedSnapshots(t *testing.T) {
	rf := newRoutingFake(&s3.GetBucketWebsiteOutput{
		RoutingRules: []types.RoutingRule{
			managedRule("current/debian/pool/"),
			managedRule("2026-07-01/debian/pool/"),
			managedRule("2026-08-11/debian/pool/"),
		},
	}, nil)

	err := rf.store().SyncPoolRoutes(context.Background(),
		[]string{"current/debian", "2026-08-11/debian"})
	if err != nil {
		t.Fatalf("SyncPoolRoutes: %v", err)
	}
	if len(rf.written) != 1 {
		t.Fatalf("wrote %d configs, want 1", len(rf.written))
	}
	got := strings.Join(prefixes(rf.written[0]), ",")
	if strings.Contains(got, "2026-07-01") {
		t.Errorf("pruned snapshot rule survived: %v", got)
	}
	if !strings.Contains(got, "current/debian/pool/") {
		t.Errorf("current rule missing: %v", got)
	}
}

// TestSyncPoolRoutesPreservesForeignRules guards against clobbering
// rules the operator added for something else.
func TestSyncPoolRoutesPreservesForeignRules(t *testing.T) {
	foreign := types.RoutingRule{
		Condition: &types.Condition{
			KeyPrefixEquals: aws.String("docs/"),
		},
		Redirect: &types.Redirect{
			ReplaceKeyPrefixWith: aws.String("documents/"),
		},
	}
	rf := newRoutingFake(&s3.GetBucketWebsiteOutput{
		RoutingRules: []types.RoutingRule{foreign},
	}, nil)

	err := rf.store().SyncPoolRoutes(context.Background(),
		[]string{"current/debian"})
	if err != nil {
		t.Fatalf("SyncPoolRoutes: %v", err)
	}
	got := strings.Join(prefixes(rf.written[0]), ",")
	if !strings.Contains(got, "docs/") {
		t.Errorf("foreign rule was dropped: %v", got)
	}
	if !strings.Contains(got, "current/debian/pool/") {
		t.Errorf("managed rule missing: %v", got)
	}
}

// TestSyncPoolRoutesKeepsCurrentWhenOverLimit covers the 50-rule cap:
// when there are more bases than rules allowed, "current" must be the
// one that survives, since that is what live clients point at.
func TestSyncPoolRoutesKeepsCurrentWhenOverLimit(t *testing.T) {
	rf := newRoutingFake(&s3.GetBucketWebsiteOutput{}, nil)

	bases := []string{}
	for i := 0; i < 80; i++ {
		bases = append(bases,
			fmt.Sprintf("2026-%02d-%02d/debian", 1+i/28, 1+i%28))
	}
	// Deliberately last, so surviving proves prioritization rather
	// than luck of ordering.
	bases = append(bases, "current/debian")

	err := rf.store().SyncPoolRoutes(context.Background(), bases)
	if err != nil {
		t.Fatalf("SyncPoolRoutes: %v", err)
	}
	rules := rf.written[0].WebsiteConfiguration.RoutingRules
	if len(rules) > maxRoutingRules {
		t.Errorf("wrote %d rules, over the %d limit",
			len(rules), maxRoutingRules)
	}
	if aws.ToString(rules[0].Condition.KeyPrefixEquals) !=
		"current/debian/pool/" {
		t.Errorf("current is not first: %v",
			aws.ToString(rules[0].Condition.KeyPrefixEquals))
	}
}

// TestSyncPoolRoutesSkipsWhenWebsiteHostingOff must not enable website
// hosting as a side effect: that would change how the whole bucket
// serves, which is not this call's decision to make.
func TestSyncPoolRoutesSkipsWhenWebsiteHostingOff(t *testing.T) {
	rf := newRoutingFake(nil, noWebsiteErr{})

	err := rf.store().SyncPoolRoutes(context.Background(),
		[]string{"current/debian"})
	if err != nil {
		t.Fatalf("SyncPoolRoutes: %v", err)
	}
	if len(rf.written) != 0 {
		t.Errorf("wrote a website config for a non-website bucket")
	}
}

// TestSyncPoolRoutesNoWriteWhenUnchanged keeps a snapshot run from
// rewriting an identical configuration every cycle.
func TestSyncPoolRoutesNoWriteWhenUnchanged(t *testing.T) {
	rf := newRoutingFake(&s3.GetBucketWebsiteOutput{
		RoutingRules: []types.RoutingRule{
			managedRule("current/debian/pool/"),
		},
	}, nil)

	err := rf.store().SyncPoolRoutes(context.Background(),
		[]string{"current/debian"})
	if err != nil {
		t.Fatalf("SyncPoolRoutes: %v", err)
	}
	if len(rf.written) != 0 {
		t.Errorf("rewrote an unchanged configuration")
	}
}

func TestSyncPoolRoutesPropagatesGetError(t *testing.T) {
	rf := newRoutingFake(nil, fmt.Errorf("access denied"))
	err := rf.store().SyncPoolRoutes(context.Background(),
		[]string{"current/debian"})
	if err == nil {
		t.Fatal("expected an error when the config cannot be read")
	}
}

func TestIsManagedRuleOnlyMatchesOurShape(t *testing.T) {
	cases := []struct {
		name string
		rule types.RoutingRule
		want bool
	}{
		{"ours", managedRule("current/debian/pool/"), true},
		{"foreign target", types.RoutingRule{
			Condition: &types.Condition{
				KeyPrefixEquals: aws.String("current/debian/pool/"),
			},
			Redirect: &types.Redirect{
				ReplaceKeyPrefixWith: aws.String("elsewhere/"),
			},
		}, false},
		{"foreign prefix", types.RoutingRule{
			Condition: &types.Condition{
				KeyPrefixEquals: aws.String("docs/"),
			},
			Redirect: &types.Redirect{
				ReplaceKeyPrefixWith: aws.String(poolPrefix),
			},
		}, false},
		{"nil condition", types.RoutingRule{
			Redirect: &types.Redirect{
				ReplaceKeyPrefixWith: aws.String(poolPrefix),
			},
		}, false},
		{"nil redirect", types.RoutingRule{
			Condition: &types.Condition{
				KeyPrefixEquals: aws.String("current/debian/pool/"),
			},
		}, false},
	}
	for _, tc := range cases {
		if got := isManagedRule(tc.rule); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOrderBasesDedupesAndPrioritizesCurrent(t *testing.T) {
	got := orderBases([]string{
		"2026-01-01/debian",
		"current/debian",
		"2026-08-11/debian",
		"current/debian",
		"",
		"/2026-05-05/debian/",
	})
	want := []string{
		"current/debian",
		"2026-08-11/debian",
		"2026-05-05/debian",
		"2026-01-01/debian",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

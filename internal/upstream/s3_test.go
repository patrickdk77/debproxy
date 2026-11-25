package upstream_test

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/debproxy/debproxy/internal/model"
	"github.com/debproxy/debproxy/internal/upstream"
)

// fakeS3 answers path-style S3 GET and HEAD requests for one bucket by
// fetching the same key from an HTTP upstream, so a suite built for an
// http mirror can be served as if it lived in a bucket. Every request
// must carry a SigV4 signature made with one of the secrets the fake was
// given: it recomputes the signature the way S3 does and answers an
// unknown key id or a wrong signature with 403. The key id of every
// request is recorded so a test can tell which credentials signed it.
type fakeS3 struct {
	srv     *httptest.Server
	secrets map[string]string
	// cacheControl, when set, goes on every 200 and 304 answer.
	cacheControl string
	// redirectKey, when set, is answered with 302 and redirectTo as the
	// Location, the way a custom endpoint might.
	redirectKey, redirectTo string

	mu       sync.Mutex
	requests int
	keyIDs   []string
	paths    []string
	statuses []int
}

func newFakeS3(t *testing.T, bucket, upstreamURL string, secrets map[string]string) *fakeS3 {
	t.Helper()
	return startFakeS3(t, bucket, upstreamURL, secrets, httptest.NewServer)
}

func newFakeS3TLS(t *testing.T, bucket, upstreamURL string, secrets map[string]string) *fakeS3 {
	t.Helper()
	return startFakeS3(t, bucket, upstreamURL, secrets, httptest.NewTLSServer)
}

func startFakeS3(t *testing.T, bucket, upstreamURL string, secrets map[string]string, start func(http.Handler) *httptest.Server) *fakeS3 {
	t.Helper()
	f := &fakeS3{secrets: secrets}
	f.srv = start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := f.authenticate(r); code != "" {
			f.fail(w, r, http.StatusForbidden, code)
			return
		}
		prefix := "/" + bucket + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			f.fail(w, r, http.StatusNotFound, "NoSuchBucket")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			f.fail(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed")
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix)
		if f.redirectKey != "" && key == f.redirectKey {
			w.Header().Set("Location", f.redirectTo)
			f.answer(w, r, http.StatusFound)
			return
		}
		resp, err := http.Get(upstreamURL + "/" + key)
		if err != nil {
			f.fail(w, r, http.StatusInternalServerError, "InternalError")
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			f.fail(w, r, http.StatusNotFound, "NoSuchKey")
			return
		}
		sum := md5.Sum(body)
		etag := `"` + hex.EncodeToString(sum[:]) + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		if f.cacheControl != "" {
			w.Header().Set("Cache-Control", f.cacheControl)
		}
		if r.Header.Get("If-None-Match") == etag {
			f.answer(w, r, http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		f.answer(w, r, http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// answer records the request's path and status and writes the status.
func (f *fakeS3) answer(w http.ResponseWriter, r *http.Request, status int) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.statuses = append(f.statuses, status)
	f.mu.Unlock()
	w.WriteHeader(status)
}

func (f *fakeS3) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	f.answer(w, r, status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

func (f *fakeS3) pathsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *fakeS3) statusesSeen() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.statuses...)
}

// authenticate records the request and checks its signature, returning
// the S3 error code for a failure or "" when the signature verifies.
func (f *fakeS3) authenticate(r *http.Request) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	auth := r.Header.Get("Authorization")
	var keyID, scope, signedHeaders, signature string
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "Credential="):
			keyID, scope, _ = strings.Cut(strings.TrimPrefix(part, "Credential="), "/")
		case strings.HasPrefix(part, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(part, "SignedHeaders=")
		case strings.HasPrefix(part, "Signature="):
			signature = strings.TrimPrefix(part, "Signature=")
		}
	}
	f.keyIDs = append(f.keyIDs, keyID)
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || keyID == "" {
		return "AccessDenied"
	}
	secret, ok := f.secrets[keyID]
	if !ok {
		return "InvalidAccessKeyId"
	}
	if !hmac.Equal([]byte(sigV4(r, secret, scope, signedHeaders)), []byte(signature)) {
		return "SignatureDoesNotMatch"
	}
	return ""
}

// sigV4 recomputes the AWS Signature Version 4 of r the way S3 does to
// check it: a canonical request over the signed headers, a string to sign
// over the credential scope, and an HMAC chain from the secret.
func sigV4(r *http.Request, secret, scope, signedHeaders string) string {
	var canonHeaders strings.Builder
	for _, name := range strings.Split(signedHeaders, ";") {
		value := r.Host
		if name != "host" {
			value = strings.Join(r.Header.Values(name), ",")
		}
		canonHeaders.WriteString(name + ":" + strings.TrimSpace(value) + "\n")
	}
	canonical := strings.Join([]string{
		r.Method,
		r.URL.EscapedPath(),
		canonicalQuery(r.URL.Query()),
		canonHeaders.String(),
		signedHeaders,
		r.Header.Get("X-Amz-Content-Sha256"),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope, hex.EncodeToString(sum[:])}, "\n")
	key := []byte("AWS4" + secret)
	for _, part := range strings.Split(scope, "/") {
		key = hmacSHA256(key, part)
	}
	return hex.EncodeToString(hmacSHA256(key, toSign))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (f *fakeS3) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// signedOnlyBy fails the test unless every request the fake saw was
// signed with keyID.
func (f *fakeS3) signedOnlyBy(t *testing.T, keyID string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.keyIDs) == 0 {
		t.Fatal("no request reached the bucket")
	}
	for i, got := range f.keyIDs {
		if got != keyID {
			t.Fatalf("request %d signed with credential %q, want %q", i+1, got, keyID)
		}
	}
}

// isolateAWSEnv keeps the host's AWS environment, shared config files
// and every other credential source out of the test.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID":                      "",
		"AWS_SECRET_ACCESS_KEY":                  "",
		"AWS_SESSION_TOKEN":                      "",
		"AWS_PROFILE":                            "",
		"AWS_REGION":                             "",
		"AWS_DEFAULT_REGION":                     "",
		"AWS_CONFIG_FILE":                        missing,
		"AWS_SHARED_CREDENTIALS_FILE":            missing,
		"AWS_EC2_METADATA_DISABLED":              "true",
		"AWS_WEB_IDENTITY_TOKEN_FILE":            "",
		"AWS_ROLE_ARN":                           "",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":     "",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN":      "",
		"AWS_CA_BUNDLE":                          "",
		"AWS_USE_FIPS_ENDPOINT":                  "",
		"AWS_USE_DUALSTACK_ENDPOINT":             "",
		"AWS_ENDPOINT_URL":                       "",
		"AWS_ENDPOINT_URL_S3":                    "",
	} {
		t.Setenv(k, v)
	}
}

func envCredentials(t *testing.T) map[string]string {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFROMENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	return map[string]string{"AKIAFROMENV": "envsecret"}
}

func s3Source(t *testing.T, fake *fakeS3, bucket string, keyring openpgp.EntityList) model.UpstreamSource {
	t.Helper()
	src := makeSource(t, "s3://"+bucket, keyring)
	src.S3 = model.S3Options{Region: "us-east-1", Endpoint: fake.srv.URL, ForcePathStyle: true}
	return src
}

func fetchDeb(t *testing.T, f *upstream.Fetcher) []byte {
	t.Helper()
	rc, err := f.FetchDebStream(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestS3UpstreamFetchesIndexAndDebWithURLCredentials(t *testing.T) {
	isolateAWSEnv(t)
	key, keyring := testKey(t)
	srvURL, _, debContent := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, map[string]string{"AKIAFROMURL": "url/secret"})

	src := makeSource(t, "s3://repo-bucket", keyring)
	src.S3 = model.S3Options{Region: "us-east-1", Endpoint: fake.srv.URL, ForcePathStyle: true}
	src.Username, src.Password = "AKIAFROMURL", "url/secret"
	f := upstream.NewFetcher(src, upstream.NewHTTPClient("", ""))

	idx, err := f.FetchIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.ByArch["amd64"]) != 1 || idx.ByArch["amd64"][0].Package != "hello" {
		t.Fatalf("index over s3 = %+v, want the hello package", idx.ByArch["amd64"])
	}
	if got := fetchDeb(t, f); string(got) != string(debContent) {
		t.Fatalf("deb over s3 = %q, want %q", got, debContent)
	}
	fake.signedOnlyBy(t, "AKIAFROMURL")
}

// The fake checks signatures, so a wrong secret with the right key id
// must be refused; this is what makes the credential checks above mean
// anything.
func TestS3UpstreamWrongSecretIsStatus403(t *testing.T) {
	isolateAWSEnv(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, map[string]string{"AKIAFROMURL": "url/secret"})

	src := makeSource(t, "s3://repo-bucket", keyring)
	src.S3 = model.S3Options{Region: "us-east-1", Endpoint: fake.srv.URL, ForcePathStyle: true}
	src.Username, src.Password = "AKIAFROMURL", "url/secre"
	f := upstream.NewFetcher(src, upstream.NewHTTPClient("", ""))
	_, err := f.FetchDebStream(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("err = %v, want status 403", err)
	}
	fake.signedOnlyBy(t, "AKIAFROMURL")
}

func TestS3UpstreamFallsBackToDefaultCredentialChain(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, debContent := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, secrets)

	f := upstream.NewFetcher(s3Source(t, fake, "repo-bucket", keyring), upstream.NewHTTPClient("", ""))
	if got := fetchDeb(t, f); string(got) != string(debContent) {
		t.Fatalf("deb over s3 = %q, want %q", got, debContent)
	}
	fake.signedOnlyBy(t, "AKIAFROMENV")
}

func TestS3UpstreamMissingObjectIsStatus404(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, secrets)

	f := upstream.NewFetcher(s3Source(t, fake, "repo-bucket", keyring), upstream.NewHTTPClient("", ""))
	_, err := f.FetchDebStream(context.Background(), "pool/main/n/none/none_1.0_amd64.deb")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("err = %v, want status 404", err)
	}
}

func TestS3UpstreamWithoutRegionFailsAtOnce(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, secrets)

	src := s3Source(t, fake, "repo-bucket", keyring)
	src.S3.Region = ""
	f := upstream.NewFetcher(src, upstream.NewHTTPClient("", ""))
	start := time.Now()
	_, err := f.FetchDebStream(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb")
	if err == nil || !strings.Contains(err.Error(), "no region") {
		t.Fatalf("err = %v, want a no-region error", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("a missing region was retried: took %v", took)
	}
}

func TestS3UpstreamWithoutAnyCredentialsFails(t *testing.T) {
	isolateAWSEnv(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, nil)

	f := upstream.NewFetcher(s3Source(t, fake, "repo-bucket", keyring), upstream.NewHTTPClient("", ""))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	_, err := f.FetchDebStream(ctx, "pool/main/h/hello/hello_1.0_amd64.deb")
	if err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("err = %v, want a credentials error", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("a credential failure was retried: took %v", took)
	}
	if n := fake.requestCount(); n != 0 {
		t.Fatalf("%d requests reached the bucket without credentials", n)
	}
}

// A custom endpoint answering a redirect must not send the fetcher to
// another bucket on the same context: the 302 comes back as a bare
// status and the Location is never requested.
func TestS3UpstreamRedirectFromBucketIsNotFollowed(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, secrets)
	fake.redirectKey = "pool/main/h/hello/hello_1.0_amd64.deb"
	fake.redirectTo = "s3://other-bucket/pool/main/h/hello/hello_1.0_amd64.deb"

	f := upstream.NewFetcher(s3Source(t, fake, "repo-bucket", keyring), upstream.NewHTTPClient("", ""))
	_, err := f.FetchDebStream(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb")
	if err == nil || !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("err = %v, want status 302", err)
	}
	for _, p := range fake.pathsSeen() {
		if strings.HasPrefix(p, "/other-bucket/") {
			t.Fatalf("the redirect was followed: request for %s", p)
		}
	}
}

// Once the cache entry has expired, the next fetch sends the validators
// back and a 304 keeps the cached index in use, through the real SDK.
func TestS3UpstreamConditionalGetGets304(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, secrets)
	fake.cacheControl = "no-cache"

	f := upstream.NewFetcherWithCache(s3Source(t, fake, "repo-bucket", keyring), upstream.NewHTTPClient("", ""), upstream.NewIndexCache())
	for i := 0; i < 2; i++ {
		idx, err := f.FetchIndex(context.Background())
		if err != nil {
			t.Fatalf("fetch %d: %v", i+1, err)
		}
		if len(idx.ByArch["amd64"]) != 1 || idx.ByArch["amd64"][0].Package != "hello" {
			t.Fatalf("fetch %d: index = %+v, want the hello package", i+1, idx.ByArch["amd64"])
		}
	}
	var got304 bool
	for _, s := range fake.statusesSeen() {
		got304 = got304 || s == http.StatusNotModified
	}
	if !got304 {
		t.Fatalf("no 304 answered; statuses %v", fake.statusesSeen())
	}
}

// An http upstream must not be able to point debproxy at a bucket: the
// redirect keeps the original request context, which carries no s3
// upstream settings, so the s3 transport refuses it before any SDK client
// exists. Credentials are in the environment so the only thing stopping
// the fetch is the refusal.
func TestS3UpstreamRefusesRedirectFromHTTPUpstream(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	fake := newFakeS3(t, "repo-bucket", srvURL, secrets)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "s3://repo-bucket"+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	f := upstream.NewFetcher(makeSource(t, redirector.URL, keyring), upstream.NewHTTPClient("", ""))
	_, err := f.FetchDebStream(context.Background(), "pool/main/h/hello/hello_1.0_amd64.deb")
	if err == nil || !strings.Contains(err.Error(), "not a request to a configured s3 upstream") {
		t.Fatalf("err = %v, want the s3 refusal", err)
	}
	if n := fake.requestCount(); n != 0 {
		t.Fatalf("%d requests reached the bucket through the redirect", n)
	}
}

// AWS_CA_BUNDLE is applied by the SDK's config loader only to its own
// client type; a bucket behind a private CA depends on it.
func TestS3UpstreamTrustsCABundle(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, debContent := buildFakeUpstream(t, key)
	fake := newFakeS3TLS(t, "repo-bucket", srvURL, secrets)

	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fake.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", bundle)

	f := upstream.NewFetcher(s3Source(t, fake, "repo-bucket", keyring), upstream.NewHTTPClient("", ""))
	if got := fetchDeb(t, f); string(got) != string(debContent) {
		t.Fatalf("deb over s3 with a CA bundle = %q, want %q", got, debContent)
	}
}

// The same s3://bucket/prefix on two endpoints is two repositories. They
// must not share one IndexCache entry, or the second upstream would be
// served the first one's index, verified with the first one's keys, and
// its own bucket would never be asked.
func TestS3UpstreamsSameBucketOnTwoEndpointsStaySeparate(t *testing.T) {
	isolateAWSEnv(t)
	secrets := envCredentials(t)
	key, keyring := testKey(t)
	srvURL, _, _ := buildFakeUpstream(t, key)
	one := newFakeS3(t, "apt", srvURL, secrets)
	two := newFakeS3(t, "apt", srvURL, secrets)
	cache := upstream.NewIndexCache()
	client := upstream.NewHTTPClient("", "")

	for i, fake := range []*fakeS3{one, two} {
		f := upstream.NewFetcherWithCache(s3Source(t, fake, "apt", keyring), client, cache)
		if _, err := f.FetchIndex(context.Background()); err != nil {
			t.Fatalf("endpoint %d: %v", i+1, err)
		}
		if fake.requestCount() == 0 {
			t.Fatalf("endpoint %d was never asked: its index came from the other endpoint's cache entry", i+1)
		}
	}
}

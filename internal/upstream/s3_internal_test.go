package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/debproxy/debproxy/internal/model"
)

type fakeS3API struct {
	get  func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	head func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
}

func (f *fakeS3API) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return f.get(in)
}

func (f *fakeS3API) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return f.head(in)
}

// serviceError is what the SDK returns when S3 answered with status.
func serviceError(status int, msg string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      errors.New(msg),
		},
		RequestID: "req-1",
	}
}

// testTransport returns a transport whose SDK clients are api, counting
// how many were built and recording the params of the last one.
func testTransport(api s3API, built *int, last *s3Params) *s3Transport {
	t := newS3Transport(newDialContext(""))
	t.newClient = func(_ context.Context, p s3Params) (s3API, error) {
		*built++
		if last != nil {
			*last = p
		}
		return api, nil
	}
	return t
}

// s3Request builds a request the way the Fetcher does for an s3 upstream,
// with the upstream's (here empty) S3 options in the context.
func s3Request(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(withS3(context.Background(), model.S3Options{}), method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestS3TransportGetMapsRequestAndResponse(t *testing.T) {
	modified := time.Date(2026, 11, 19, 15, 4, 0, 0, time.UTC)
	var gotIn *s3.GetObjectInput
	api := &fakeS3API{get: func(in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		gotIn = in
		return &s3.GetObjectOutput{
			Body:          io.NopCloser(strings.NewReader("deb bytes")),
			ContentLength: aws.Int64(9),
			ContentType:   aws.String("application/octet-stream"),
			ETag:          aws.String(`"abc"`),
			LastModified:  aws.Time(modified),
			CacheControl:  aws.String("max-age=60"),
			AcceptRanges:  aws.String("bytes"),
		}, nil
	}}
	var built int
	tr := testTransport(api, &built, nil)

	req := s3Request(t, http.MethodGet, "s3://bucket/pool/main/h/hello/hello_1.0_amd64.deb")
	req.Header.Set("Range", "bytes=0-3")
	req.Header.Set("If-None-Match", `"old"`)
	req.Header.Set("If-Modified-Since", "Wed, 18 Nov 2026 15:40:00 GMT")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if aws.ToString(gotIn.Bucket) != "bucket" || aws.ToString(gotIn.Key) != "pool/main/h/hello/hello_1.0_amd64.deb" {
		t.Fatalf("GetObject got bucket %q key %q", aws.ToString(gotIn.Bucket), aws.ToString(gotIn.Key))
	}
	if aws.ToString(gotIn.Range) != "bytes=0-3" || aws.ToString(gotIn.IfNoneMatch) != `"old"` {
		t.Fatalf("Range/If-None-Match not passed through: %+v", gotIn)
	}
	if gotIn.IfModifiedSince == nil || !gotIn.IfModifiedSince.Equal(time.Date(2026, 11, 18, 15, 40, 0, 0, time.UTC)) {
		t.Fatalf("If-Modified-Since not passed through: %v", gotIn.IfModifiedSince)
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength != 9 {
		t.Fatalf("status %d length %d, want 200 and 9", resp.StatusCode, resp.ContentLength)
	}
	want := map[string]string{
		"Content-Length": "9",
		"Content-Type":   "application/octet-stream",
		"ETag":           `"abc"`,
		"Last-Modified":  "Thu, 19 Nov 2026 15:04:00 GMT",
		"Cache-Control":  "max-age=60",
		"Accept-Ranges":  "bytes",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "deb bytes" {
		t.Fatalf("body = %q", body)
	}
	if resp.Request != req || resp.Proto != "HTTP/1.1" {
		t.Fatal("response is not tied to the request as an HTTP/1.1 reply")
	}
}

func TestS3TransportPartialContent(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{
			Body:          io.NopCloser(strings.NewReader("deb")),
			ContentLength: aws.Int64(3),
			ContentRange:  aws.String("bytes 0-2/9"),
		}, nil
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != "bytes 0-2/9" {
		t.Fatalf("status %d Content-Range %q, want 206 and bytes 0-2/9", resp.StatusCode, resp.Header.Get("Content-Range"))
	}
}

func TestS3TransportGetWithoutLengthIsUnbounded(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("x"))}, nil
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("ContentLength %d header %q, want -1 and none", resp.ContentLength, resp.Header.Get("Content-Length"))
	}
}

func TestS3TransportServiceErrorBecomesStatus(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return nil, serviceError(status, "api error from S3")
		}}
		var built int
		resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
		if err != nil {
			t.Fatalf("status %d: RoundTrip returned error %v, want a response", status, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		wantBody := status != http.StatusNotModified
		if resp.StatusCode != status || strings.Contains(string(body), "api error from S3") != wantBody {
			t.Fatalf("got status %d body %q, want %d with the service message (%v)", resp.StatusCode, body, status, wantBody)
		}
	}
}

func TestS3TransportSendErrorIsReturnedForRetry(t *testing.T) {
	dialErr := errors.New("dial tcp: connection refused")
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return nil, &smithyhttp.RequestSendError{Err: dialErr}
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if resp != nil || !errors.Is(err, dialErr) {
		t.Fatalf("got resp %v err %v, want nil and the dial error", resp, err)
	}
	if !isRetryableErr(err) {
		t.Fatal("a network error from the SDK must stay retryable")
	}
}

// An error that is neither a service answer nor a send failure, such as a
// credential lookup that found nothing, repeats on every attempt and must
// not cost the retry budget.
func TestS3TransportOtherErrorIsPermanent(t *testing.T) {
	credErr := errors.New("get identity: get credentials: no EC2 IMDS role found")
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) { return nil, credErr }}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if resp != nil || !errors.Is(err, credErr) {
		t.Fatalf("got resp %v err %v, want nil and the credential error", resp, err)
	}
	if isRetryableErr(err) {
		t.Fatal("a credential error from the SDK must not be retried")
	}
}

// A 3xx answer from the service keeps its status but not its Location:
// the http.Client would follow it with this request's context, marker and
// all, so a custom endpoint could send the fetcher to another bucket.
func TestS3TransportRedirectLosesLocation(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return nil, &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": {"s3://other-bucket/k"}, "Etag": {`"abc"`}},
				}},
				Err: errors.New("Found"),
			},
		}
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "" || resp.Header.Get("ETag") != `"abc"` {
		t.Fatalf("status %d headers %v, want 302 without Location", resp.StatusCode, resp.Header)
	}
}

func TestS3TransportHeadPartialContent(t *testing.T) {
	api := &fakeS3API{head: func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
		return &s3.HeadObjectOutput{ContentLength: aws.Int64(3), ContentRange: aws.String("bytes 0-2/9")}, nil
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodHead, "s3://bucket/k"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != "bytes 0-2/9" {
		t.Fatalf("status %d Content-Range %q, want 206 and bytes 0-2/9", resp.StatusCode, resp.Header.Get("Content-Range"))
	}
}

func TestS3TransportHead(t *testing.T) {
	api := &fakeS3API{
		get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			t.Fatal("HEAD must not call GetObject")
			return nil, nil
		},
		head: func(in *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
			if aws.ToString(in.Key) != "k" {
				t.Fatalf("HeadObject key %q", aws.ToString(in.Key))
			}
			return &s3.HeadObjectOutput{ContentLength: aws.Int64(42), ETag: aws.String(`"e"`)}, nil
		},
	}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodHead, "s3://bucket/k"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.ContentLength != 42 || resp.Header.Get("ETag") != `"e"` || len(body) != 0 {
		t.Fatalf("status %d length %d etag %q body %d bytes", resp.StatusCode, resp.ContentLength, resp.Header.Get("ETag"), len(body))
	}
}

func TestS3TransportHeadErrorBecomesStatus(t *testing.T) {
	api := &fakeS3API{head: func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
		return nil, serviceError(http.StatusNotFound, "NotFound")
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodHead, "s3://bucket/k"))
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %v / %v, want a 404 response", resp, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) != 0 {
		t.Fatalf("HEAD error response has a %d byte body", len(body))
	}
}

func TestS3TransportHeadPassesConditionalHeaders(t *testing.T) {
	var gotIn *s3.HeadObjectInput
	api := &fakeS3API{head: func(in *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
		gotIn = in
		return &s3.HeadObjectOutput{}, nil
	}}
	var built int
	req := s3Request(t, http.MethodHead, "s3://bucket/k")
	req.Header.Set("Range", "bytes=0-3")
	req.Header.Set("If-None-Match", `"old"`)
	req.Header.Set("If-Modified-Since", "Wed, 18 Nov 2026 15:40:00 GMT")
	resp, err := testTransport(api, &built, nil).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if aws.ToString(gotIn.Range) != "bytes=0-3" || aws.ToString(gotIn.IfNoneMatch) != `"old"` || gotIn.IfModifiedSince == nil {
		t.Fatalf("HeadObject input lacks the conditional headers: %+v", gotIn)
	}
}

func TestS3TransportRejectsOtherMethods(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		t.Fatal("POST must not reach S3")
		return nil, nil
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodPost, "s3://bucket/k"))
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("got %v / %v, want 405", resp, err)
	}
	resp.Body.Close()
}

func TestS3TransportRejectsMissingBucketOrKey(t *testing.T) {
	var built int
	tr := testTransport(&fakeS3API{}, &built, nil)
	for _, u := range []string{"s3://bucket", "s3://bucket/", "s3:///key"} {
		resp, err := tr.RoundTrip(s3Request(t, http.MethodGet, u))
		if err == nil || resp != nil {
			t.Fatalf("%s: got %v / %v, want an error", u, resp, err)
		}
		if isRetryableErr(err) {
			t.Fatalf("%s: a malformed URL must not be retried: %v", u, err)
		}
	}
	if built != 0 {
		t.Fatalf("built %d clients for malformed URLs", built)
	}
}

func TestS3TransportClientErrorIsPermanent(t *testing.T) {
	tr := newS3Transport(newDialContext(""))
	tr.newClient = func(context.Context, s3Params) (s3API, error) { return nil, errors.New("no region") }
	resp, err := tr.RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if err == nil || resp != nil {
		t.Fatalf("got %v / %v, want an error", resp, err)
	}
	if !strings.Contains(err.Error(), "bucket") || !strings.Contains(err.Error(), "no region") {
		t.Fatalf("error %q should name the bucket and the cause", err)
	}
	if isRetryableErr(err) {
		t.Fatal("a client setup error must not be retried")
	}
}

func TestS3TransportBuildsOneClientPerCredentialsAndOptions(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	var built int
	var last s3Params
	tr := testTransport(api, &built, &last)

	do := func(user, pass string, opts model.S3Options) {
		t.Helper()
		req := s3Request(t, http.MethodGet, "s3://bucket/k")
		req = req.WithContext(withS3(req.Context(), opts))
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	east := model.S3Options{Region: "us-east-1"}
	do("", "", east)
	do("", "", east)
	if built != 1 || last.accessKey != "" || last.Region != "us-east-1" {
		t.Fatalf("default-chain client: built %d, params %+v", built, last)
	}
	do("AKIA", "secret", east)
	do("AKIA", "secret", east)
	if built != 2 || last.accessKey != "AKIA" || last.secretKey != "secret" {
		t.Fatalf("static-credentials client: built %d, params %+v", built, last)
	}
	do("AKIA", "secret", model.S3Options{Region: "us-east-1", Endpoint: "http://minio:9000", ForcePathStyle: true})
	if built != 3 || last.Endpoint != "http://minio:9000" || !last.ForcePathStyle {
		t.Fatalf("endpoint client: built %d, params %+v", built, last)
	}
	do("", "", model.S3Options{})
	if built != 4 || last != (s3Params{}) {
		t.Fatalf("no-options client: built %d, params %+v", built, last)
	}
}

// A request whose context was not marked by the Fetcher (withS3) is a
// redirect from an http upstream or some other caller of the shared
// client; it must be refused before any SDK client is built, even with
// credentials on it.
func TestS3TransportRefusesRequestWithoutUpstreamContext(t *testing.T) {
	var built int
	tr := testTransport(&fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		t.Fatal("a request without the s3 upstream context reached S3")
		return nil, nil
	}}, &built, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "s3://bucket/k", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("AKIA", "secret")
	resp, err := tr.RoundTrip(req)
	if err == nil || resp != nil {
		t.Fatalf("got %v / %v, want an error", resp, err)
	}
	if !strings.Contains(err.Error(), "not a request to a configured s3 upstream") || isRetryableErr(err) {
		t.Fatalf("want a permanent refusal, got %v", err)
	}
	if built != 0 {
		t.Fatalf("built %d clients for a refused request", built)
	}
}

func TestS3TransportSecretWithColonSurvivesBasicAuth(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	var built int
	var last s3Params
	req := s3Request(t, http.MethodGet, "s3://bucket/k")
	req.SetBasicAuth("AKIA", "se:cr:et")
	resp, err := testTransport(api, &built, &last).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if last.accessKey != "AKIA" || last.secretKey != "se:cr:et" {
		t.Fatalf("credentials = %q/%q, want AKIA/se:cr:et", last.accessKey, last.secretKey)
	}
}

// A ResponseError with a success status is a 2xx the SDK could not decode;
// handing it back as a 200 with the error text as body would make the
// Fetcher report a hash mismatch on what is really a broken reply.
func TestS3TransportSuccessStatusErrorIsNotAResponse(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return nil, serviceError(http.StatusOK, "deserialization failed")
	}}
	var built int
	resp, err := testTransport(api, &built, nil).RoundTrip(s3Request(t, http.MethodGet, "s3://bucket/k"))
	if resp != nil || err == nil || !strings.Contains(err.Error(), "deserialization failed") {
		t.Fatalf("got %v / %v, want the error back", resp, err)
	}
}

func TestS3TransportNotModifiedKeepsValidators(t *testing.T) {
	api := &fakeS3API{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return nil, &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{
					StatusCode: http.StatusNotModified,
					Header: http.Header{
						"Etag":           {`"abc"`},
						"Last-Modified":  {"Thu, 19 Nov 2026 15:04:00 GMT"},
						"Content-Length": {"0"},
					},
				}},
				Err: errors.New("NotModified"),
			},
		}
	}}
	var built int
	req := s3Request(t, http.MethodGet, "s3://bucket/k")
	req.Header.Set("If-None-Match", `"abc"`)
	resp, err := testTransport(api, &built, nil).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Fatalf("status %d with a %d byte body, want an empty 304", resp.StatusCode, len(body))
	}
	if resp.Header.Get("ETag") != `"abc"` || resp.Header.Get("Last-Modified") != "Thu, 19 Nov 2026 15:04:00 GMT" {
		t.Fatalf("304 lost its validators: %v", resp.Header)
	}
}

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

func TestS3TransportClosesRequestBody(t *testing.T) {
	var built int
	tr := testTransport(&fakeS3API{}, &built, nil)
	body := &closeRecorder{Reader: strings.NewReader("x")}
	req := s3Request(t, http.MethodPost, "s3://bucket/k")
	req.Body = body
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !body.closed {
		t.Fatal("RoundTrip did not close the request body it never sent")
	}
}

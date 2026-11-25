package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/debproxy/debproxy/internal/model"
)

// withS3 stores the connection settings of an s3:// upstream in ctx so the
// S3 transport can pick the right endpoint, region and addressing style for
// every request made with that context. It is also the mark that a request
// was made to a configured s3 upstream: the transport refuses an s3:// URL
// whose context lacks it, which keeps a redirect from an http upstream to
// s3:// from being fetched with this process's AWS credentials.
func withS3(ctx context.Context, opts model.S3Options) context.Context {
	return context.WithValue(ctx, s3OptionsKey, opts)
}

// s3Params identifies one SDK client: where it connects and as whom.
type s3Params struct {
	model.S3Options
	accessKey string
	secretKey string
}

// s3API is the part of the S3 client the transport uses; tests swap in a
// fake through s3Transport.newClient.
type s3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// s3Transport serves s3://bucket/key requests through the AWS SDK and
// answers them as HTTP responses, so the Fetcher needs no second code path
// for an S3 upstream: GET becomes GetObject (with Range, If-None-Match and
// If-Modified-Since passed through), HEAD becomes HeadObject, and an error
// the service answered becomes a response with that status (404 for a
// missing key, 304 for an unchanged one, 403 for denied access). Network
// errors are returned as errors, so retryTransport retries them the same
// way it retries an http upstream; the SDK's own retries are turned off
// for that reason.
//
// Credentials come from the request's Basic Auth pair, which the Fetcher
// fills from the upstream's username and password (an s3:// URL's
// "key:secret@" part lands there at config load); with none, the AWS
// default credential chain applies. One SDK client is built per distinct
// combination of credentials and connection settings and kept for the
// life of the transport.
//
// Only a request whose context carries withS3 is served. The Fetcher sets
// it for its own requests to an s3 upstream; a redirect from an http
// upstream keeps the original context, so a Location of s3://... is
// refused instead of being fetched with the default credential chain.
type s3Transport struct {
	httpClient *awshttp.BuildableClient
	newClient  func(ctx context.Context, p s3Params) (s3API, error)

	mu      sync.Mutex
	clients map[s3Params]s3API
}

// newS3Transport returns a transport whose SDK connections dial through
// dialContext. The SDK's own client type is used so the config loader can
// add a custom CA bundle (AWS_CA_BUNDLE, or ca_bundle in the shared
// config) and keep its redirect handling, which drops the security token
// when a redirect leaves the signed host.
func newS3Transport(dialContext dialFunc) *s3Transport {
	t := &s3Transport{
		httpClient: awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
			tr.DialContext = dialContext
			tr.ResponseHeaderTimeout = 30 * time.Second
		}),
		clients: map[s3Params]s3API{},
	}
	t.newClient = t.sdkClient
	return t
}

func (t *s3Transport) sdkClient(ctx context.Context, p s3Params) (s3API, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithHTTPClient(t.httpClient),
		awsconfig.WithRetryMaxAttempts(1),
	}
	if p.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(p.Region))
	}
	if p.accessKey != "" || p.secretKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(p.accessKey, p.secretKey, "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("no region: set s3.region on the upstream, storage.s3.region, or AWS_REGION")
	}
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if p.Endpoint != "" {
			o.BaseEndpoint = aws.String(p.Endpoint)
		}
		if strings.HasPrefix(strings.ToLower(p.Endpoint), "http://") {
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		}
		o.UsePathStyle = p.ForcePathStyle
	}), nil
}

func (t *s3Transport) client(ctx context.Context, p s3Params) (s3API, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.clients[p]; ok {
		return c, nil
	}
	c, err := t.newClient(ctx, p)
	if err != nil {
		return nil, err
	}
	t.clients[p] = c
	return c, nil
}

func (t *s3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	ctx := req.Context()
	opts, ok := ctx.Value(s3OptionsKey).(model.S3Options)
	if !ok {
		return nil, permanentError{fmt.Errorf("s3 upstream: refusing %s: not a request to a configured s3 upstream", req.URL.Redacted())}
	}
	p := s3Params{S3Options: opts}
	if user, pass, ok := req.BasicAuth(); ok {
		p.accessKey, p.secretKey = user, pass
	}
	bucket := req.URL.Host
	key := strings.TrimPrefix(req.URL.Path, "/")
	if bucket == "" || key == "" {
		return nil, permanentError{fmt.Errorf("s3 upstream: %q has no bucket or key", req.URL.Redacted())}
	}
	client, err := t.client(ctx, p)
	if err != nil {
		return nil, permanentError{fmt.Errorf("s3 upstream %s: %w", bucket, err)}
	}

	rng, ifNoneMatch, ifModifiedSince := conditionalHeaders(req.Header)
	switch req.Method {
	case http.MethodGet:
		in := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key),
			Range: rng, IfNoneMatch: ifNoneMatch, IfModifiedSince: ifModifiedSince}
		out, err := client.GetObject(ctx, in)
		if err != nil {
			return s3ErrorResponse(req, err)
		}
		h := s3Headers(out.ContentType, out.ETag, out.LastModified, out.CacheControl, out.AcceptRanges, out.ContentLength)
		return s3Response(req, rangeStatus(h, out.ContentRange), h, out.Body, aws.ToInt64(out.ContentLength)), nil
	case http.MethodHead:
		in := &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key),
			Range: rng, IfNoneMatch: ifNoneMatch, IfModifiedSince: ifModifiedSince}
		out, err := client.HeadObject(ctx, in)
		if err != nil {
			return s3ErrorResponse(req, err)
		}
		h := s3Headers(out.ContentType, out.ETag, out.LastModified, out.CacheControl, out.AcceptRanges, out.ContentLength)
		return s3Response(req, rangeStatus(h, out.ContentRange), h, http.NoBody, aws.ToInt64(out.ContentLength)), nil
	default:
		return s3Response(req, http.StatusMethodNotAllowed, http.Header{}, http.NoBody, 0), nil
	}
}

// conditionalHeaders reads the request headers GetObject and HeadObject
// both accept.
func conditionalHeaders(h http.Header) (rng, ifNoneMatch *string, ifModifiedSince *time.Time) {
	if v := h.Get("Range"); v != "" {
		rng = aws.String(v)
	}
	if v := h.Get("If-None-Match"); v != "" {
		ifNoneMatch = aws.String(v)
	}
	if v := h.Get("If-Modified-Since"); v != "" {
		if ts, err := http.ParseTime(v); err == nil {
			ifModifiedSince = aws.Time(ts)
		}
	}
	return rng, ifNoneMatch, ifModifiedSince
}

// rangeStatus adds Content-Range to h and returns 206 when the service
// answered a Range request, 200 otherwise.
func rangeStatus(h http.Header, contentRange *string) int {
	if contentRange == nil {
		return http.StatusOK
	}
	h.Set("Content-Range", *contentRange)
	return http.StatusPartialContent
}

// s3ErrorResponse turns an error the service answered with a 3xx, 4xx or
// 5xx status into the matching HTTP response, keeping the headers of that
// answer (a 304 carries the validators the next conditional request
// needs) except Location: the http.Client would follow it on the same
// context, so a custom endpoint answering 302 could send the fetcher to
// another bucket. Any other error goes through sdkError: a connection
// failure, missing credentials, or a 2xx the SDK could not decode, which
// must not be served as a success.
func s3ErrorResponse(req *http.Request, err error) (*http.Response, error) {
	var re *awshttp.ResponseError
	if !errors.As(err, &re) || re.Response == nil || re.Response.Response == nil {
		return nil, sdkError(err)
	}
	status := re.HTTPStatusCode()
	if status < 300 {
		return nil, sdkError(err)
	}
	h := http.Header{}
	for k, v := range re.Response.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding", "Location":
			continue
		}
		h[http.CanonicalHeaderKey(k)] = v
	}
	if status == http.StatusNotModified || req.Method == http.MethodHead {
		return s3Response(req, status, h, http.NoBody, 0), nil
	}
	msg := err.Error()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(msg)))
	return s3Response(req, status, h, io.NopCloser(strings.NewReader(msg)), int64(len(msg))), nil
}

// sdkError decides whether retryTransport may retry an SDK error that
// carried no service answer. A failure to send the request (dial, TLS,
// response-header timeout) is transient and returned as is; anything else
// (no credentials, a bad profile, an undecodable answer) would repeat on
// every attempt and is wrapped as permanentError.
func sdkError(err error) error {
	var send *smithyhttp.RequestSendError
	if errors.As(err, &send) {
		return err
	}
	return permanentError{err}
}

func s3Headers(contentType, etag *string, lastModified *time.Time, cacheControl, acceptRanges *string, contentLength *int64) http.Header {
	h := http.Header{}
	if contentType != nil {
		h.Set("Content-Type", *contentType)
	}
	if etag != nil {
		h.Set("ETag", *etag)
	}
	if lastModified != nil {
		h.Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
	}
	if cacheControl != nil {
		h.Set("Cache-Control", *cacheControl)
	}
	if acceptRanges != nil {
		h.Set("Accept-Ranges", *acceptRanges)
	}
	if contentLength != nil {
		h.Set("Content-Length", strconv.FormatInt(*contentLength, 10))
	}
	return h
}

func s3Response(req *http.Request, status int, h http.Header, body io.ReadCloser, contentLength int64) *http.Response {
	if h.Get("Content-Length") == "" {
		contentLength = -1
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          body,
		ContentLength: contentLength,
		Request:       req,
	}
}

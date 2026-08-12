package s3store

import (
	"net/http"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"

	"github.com/debproxy/debproxy/internal/config"
)

// DefaultResponseHeaderTimeout bounds how long an S3 request may wait
// for response headers before failing.
//
// The SDK's own default transport sets TLSHandshakeTimeout,
// IdleConnTimeout and ExpectContinueTimeout, but no
// ResponseHeaderTimeout -- so once a request is on the wire there is
// nothing capping how long it can sit without a reply. In production
// that showed up as HeadObject and GetObject calls hanging for over
// half a minute and only ending when the client that triggered them
// gave up, reported as "StatusCode: 0 ... context canceled" because no
// response was ever received. Bounding it here turns an unbounded hang
// into a prompt, retryable error.
//
// This deliberately caps time-to-first-byte, not total transfer time,
// so streaming a large .deb body is unaffected no matter how long the
// body takes to read.
const DefaultResponseHeaderTimeout = 30 * time.Second

// newHTTPClient builds the HTTP client used for every S3 request,
// starting from the SDK's own transport defaults (connection pooling,
// TLS settings, proxy handling) and adding the response-header bound
// the SDK leaves unset.
func newHTTPClient(cfg config.S3Config) *awshttp.BuildableClient {
	timeout := cfg.ResponseHeaderTimeoutDuration()
	if timeout <= 0 {
		timeout = DefaultResponseHeaderTimeout
	}
	return awshttp.NewBuildableClient().WithTransportOptions(
		func(tr *http.Transport) {
			tr.ResponseHeaderTimeout = timeout
		})
}

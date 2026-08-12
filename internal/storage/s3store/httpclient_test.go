package s3store

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/debproxy/debproxy/internal/config"
)

func netListen() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func newGETRequest(url string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, url, nil)
}

func TestNewHTTPClientUsesDefaultWhenUnset(t *testing.T) {
	for _, in := range []string{"", "0", "not-a-duration"} {
		cfg := config.S3Config{ResponseHeaderTimeout: in}
		if got := cfg.ResponseHeaderTimeoutDuration(); got != 0 {
			t.Errorf("%q parsed to %v, want 0", in, got)
		}
		if c := newHTTPClient(cfg); c == nil {
			t.Errorf("%q: nil client", in)
		}
	}
}

func TestResponseHeaderTimeoutParsesExplicitValue(t *testing.T) {
	cfg := config.S3Config{ResponseHeaderTimeout: "5s"}
	if got := cfg.ResponseHeaderTimeoutDuration(); got != 5*time.Second {
		t.Errorf("got %v, want 5s", got)
	}
}

// TestHTTPClientBoundsHeaderWait is the regression test for the
// production hang: a server that accepts the connection and then never
// sends response headers must fail promptly rather than hanging until
// the caller gives up.
func TestHTTPClientBoundsHeaderWait(t *testing.T) {
	cfg := config.S3Config{ResponseHeaderTimeout: "300ms"}
	client := newHTTPClient(cfg)

	// A listener that accepts and then goes silent, which is exactly
	// what produced "StatusCode: 0" for tens of seconds.
	ln, err := netListen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold it open, never reply.
			_ = conn
		}
	}()

	req, err := newGETRequest("http://" + ln.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected a timeout error, got a response")
	}
	if elapsed > 5*time.Second {
		t.Errorf("waited %v before failing; header timeout not applied",
			elapsed)
	}
}

package testsupport

import (
	"fmt"
	"net/http"
	"time"
)

// MinIOImage is the S3-compatible server image the storage tests run against.
// MinIO speaks the real S3 API, so tests exercise the actual AWS SDK code
// paths and real S3 error codes/semantics -- not a hand-rolled fake whose
// error codes we'd merely be guessing at.
const MinIOImage = "minio/minio:latest"

// Fixed root credentials for the disposable MinIO container. Tests wire these
// into the AWS credential chain (via env) before constructing the S3 store.
const (
	MinIOAccessKey = "debproxytestkey"
	MinIOSecretKey = "debproxytestsecret"
)

// StartMinIO launches a disposable MinIO container bound to a Docker-assigned
// free host port, waits for its health endpoint, and returns the
// "host:port" address plus a stop function that removes the container. An
// error is returned if Docker is unavailable or the image cannot be
// pulled/started.
func StartMinIO() (addr string, stop func(), err error) {
	id, err := runDetachedContainer(MinIOImage,
		[]string{
			"-p", "127.0.0.1::9000",
			"-e", "MINIO_ROOT_USER=" + MinIOAccessKey,
			"-e", "MINIO_ROOT_PASSWORD=" + MinIOSecretKey,
		},
		[]string{"server", "/data"},
	)
	if err != nil {
		return "", nil, err
	}
	stop = func() { removeContainer(id) }

	addr, err = containerHostPort(id, "9000/tcp")
	if err != nil {
		stop()
		return "", nil, err
	}

	if err := waitMinIOReady(addr, 40*time.Second); err != nil {
		stop()
		return "", nil, err
	}
	return addr, stop, nil
}

func waitMinIOReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := "http://" + addr + "/minio/health/ready"
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("health status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("minio at %s did not become ready within %s: %w", addr, timeout, lastErr)
}

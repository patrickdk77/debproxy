// Package testsupport provides shared test infrastructure. It is imported
// only from _test.go files, so it is never linked into the production
// binary.
package testsupport

import (
	"fmt"
	"os/exec"
	"strings"
)

// runDetachedContainer pulls the image (a no-op if already present) and starts
// a detached container, returning its ID. Pulling first is important: when
// `docker run` has to pull, its combined output interleaves pull-progress
// lines with the container ID, so we could not treat the whole output as the
// ID. With the image already local, run prints only the ID -- and we still
// defensively take the last non-empty line.
// dockerArgs are flags for `docker run` (before the image); cmdArgs are passed
// to the container's entrypoint (after the image).
func runDetachedContainer(image string, dockerArgs, cmdArgs []string) (id string, err error) {
	if out, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker pull %s: %w\n%s", image, err, out)
	}

	args := append([]string{"run", "-d", "--rm"}, dockerArgs...)
	args = append(args, image)
	args = append(args, cmdArgs...)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run %s: %w\n%s", image, err, out)
	}
	return lastNonEmptyLine(string(out)), nil
}

// containerHostPort returns the "127.0.0.1:PORT" mapping for the container's
// given port (e.g. "6379/tcp").
func containerHostPort(id, containerPort string) (string, error) {
	out, err := exec.Command("docker", "port", id, containerPort).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker port: %w\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, "127.0.0.1:") {
			return strings.TrimSpace(line), nil
		}
	}
	return "", fmt.Errorf("no 127.0.0.1 port mapping found in: %q", out)
}

func removeContainer(id string) {
	if id != "" {
		_ = exec.Command("docker", "rm", "-f", id).Run()
	}
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

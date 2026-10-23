package api

import (
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureSlog routes the default logger into a buffer for one test.
func captureSlog(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// An admin API whose failed logins and lockouts leave no log record has no
// audit trail: the e2e run sent ten wrong passwords, tripped the throttle
// and was refused a permission, and the server log recorded none of it.
func TestGuardLogsInvalidCredentials(t *testing.T) {
	buf := captureSlog(t)
	a := newGuardTestAPI(t)
	h := a.guard(ResSnapshot, ActCreate, okHandler)
	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.1:1000"))

	got := buf.String()
	for _, want := range []string{"level=WARN", "user=alice", "peer=10.0.0.1", "reason=invalid_credentials", "resource=snapshot", "action=create"} {
		if !strings.Contains(got, want) {
			t.Errorf("log lacks %q:\n%s", want, got)
		}
	}
}

func TestGuardLogsThrottledAttempt(t *testing.T) {
	buf := captureSlog(t)
	a := newGuardTestAPI(t)
	a.throttle = newAuthThrottle(1, time.Minute)
	h := a.guard(ResSnapshot, ActCreate, okHandler)
	h(httptest.NewRecorder(), guardReq("alice", "wrong", "10.0.0.1:1000"))
	h(httptest.NewRecorder(), guardReq("alice", "s3cret", "10.0.0.1:1001"))

	if !strings.Contains(buf.String(), "reason=throttled") {
		t.Errorf("lockout not logged:\n%s", buf.String())
	}
}

func TestGuardLogsNotPermitted(t *testing.T) {
	buf := captureSlog(t)
	a := newGuardTestAPI(t)
	a.cfg.API[ResCleanup] = map[string][]string{ActRun: {"bob"}}
	h := a.guard(ResCleanup, ActRun, okHandler)
	h(httptest.NewRecorder(), guardReq("alice", "s3cret", "10.0.0.1:1000"))

	got := buf.String()
	for _, want := range []string{"level=WARN", "user=alice", "reason=not_permitted", "resource=cleanup"} {
		if !strings.Contains(got, want) {
			t.Errorf("log lacks %q:\n%s", want, got)
		}
	}
}

// The failure record must not become a success record: a good login is
// routine traffic for the access log, not a warning.
func TestGuardDoesNotWarnOnSuccess(t *testing.T) {
	buf := captureSlog(t)
	a := newGuardTestAPI(t)
	h := a.guard(ResSnapshot, ActCreate, okHandler)
	rec := httptest.NewRecorder()
	h(rec, guardReq("alice", "s3cret", "10.0.0.1:1000"))
	if rec.Code != 200 {
		t.Fatalf("setup: status %d", rec.Code)
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("successful login produced a warning:\n%s", buf.String())
	}
}

// A username is attacker-chosen text; it must not be able to forge log
// lines. slog's text handler quotes it, and this pins that.
func TestGuardLogsUsernameQuoted(t *testing.T) {
	buf := captureSlog(t)
	a := newGuardTestAPI(t)
	h := a.guard(ResSnapshot, ActCreate, okHandler)
	h(httptest.NewRecorder(), guardReq("alice\nlevel=INFO msg=forged", "wrong", "10.0.0.1:1000"))

	got := buf.String()
	if strings.Contains(got, "\nlevel=INFO") {
		t.Errorf("username injected a log line:\n%s", got)
	}
	if !strings.Contains(got, "reason=invalid_credentials") {
		t.Errorf("failure not logged:\n%s", got)
	}
}

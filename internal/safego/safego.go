// Package safego wraps background work with panic recovery and structured
// logging, so a bug in one cycle of a long-lived goroutine (a scheduler tick,
// a live-cache rebuild, a webhook fire, a pub/sub message handler) degrades
// -- that cycle fails, logged, and the next one still runs -- instead of
// taking the whole process down. net/http already recovers panics per
// request on its own goroutine; this covers the gap that leaves open: detached
// goroutines spawned with a bare `go` outside of an active request, which
// previously had no recovery anywhere in this codebase.
package safego

import (
	"log/slog"
	"runtime/debug"
)

// Go runs fn in a new goroutine, recovering any panic and logging it (with
// name identifying which background task panicked, plus a stack trace)
// rather than letting it crash the process.
func Go(name string, fn func()) {
	go Run(name, fn)
}

// Run executes fn in the calling goroutine with the same panic recovery as
// Go. Use this when the caller already owns the goroutine (e.g. one
// iteration of a persistent scheduler loop) and wants just that cycle's
// panic contained, rather than the whole loop aborting silently.
func Run(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("recovered from panic", "task", name, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn()
}

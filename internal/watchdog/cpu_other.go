//go:build !unix

package watchdog

import "time"

// processCPUTime has no portable implementation off unix. Callers fall
// back to reporting the stall without a cause verdict.
func processCPUTime() (time.Duration, bool) { return 0, false }

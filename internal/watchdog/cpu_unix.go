//go:build unix

package watchdog

import (
	"syscall"
	"time"
)

// processCPUTime returns cumulative CPU time (user+system, summed
// across all threads) consumed by this process. This is what
// distinguishes a process that was descheduled from one that was
// burning its whole CPU budget.
func processCPUTime() (time.Duration, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(
		syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	user := time.Duration(ru.Utime.Sec)*time.Second +
		time.Duration(ru.Utime.Usec)*time.Microsecond
	sys := time.Duration(ru.Stime.Sec)*time.Second +
		time.Duration(ru.Stime.Usec)*time.Microsecond
	return user + sys, true
}

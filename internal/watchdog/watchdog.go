// Package watchdog detects and explains stalls where this process
// stops being scheduled.
//
// A stall that freezes every goroutine at once -- CPU quota throttling,
// kernel memory reclaim on a cgroup at its limit, a node-level pause --
// is invisible from outside the process. The kernel keeps completing
// TCP handshakes into the accept backlog with no help from the
// application, so a client sees a connection that is established and
// then never answered, and a health probe reports a timeout while the
// process is provably alive. Nothing inside gets a chance to say what
// happened, and by the time anyone looks it is running normally again.
//
// The watchdog measures it the only way that works from inside: it
// sleeps a fixed interval in a loop and compares the wall time that
// actually elapsed against the interval it asked for. Overshoot past a
// threshold means this goroutine went unscheduled for that long, and
// since it needs almost no CPU to wake up, nothing else was running
// either.
//
// The overshoot alone says a stall happened. Pairing it with the CPU
// time the process consumed across the same window says why:
//
//   - overshoot large, CPU time near zero -- the process was not
//     running. Something outside it took the CPU away: CFS quota
//     throttling, cgroup memory reclaim, node pressure. No amount of
//     application-level work explains this.
//   - overshoot large, CPU time near the full window times GOMAXPROCS
//     -- the process was running flat out and this goroutine simply
//     lost the race for a P. That is our own workload saturating the
//     CPU budget, and the accompanying stack dump names the callers.
//
// That distinction is the whole point: it decides whether to look
// inside the program or outside it, without guessing.
package watchdog

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

const (
	// DefaultInterval is how often the loop wakes to measure. Short
	// enough to resolve a stall well under a probe timeout, cheap
	// enough to run forever.
	DefaultInterval = 1 * time.Second

	// DefaultThreshold is the overshoot past Interval that counts as
	// a stall. Ordinary scheduling jitter is microseconds, so a full
	// second of overshoot is unambiguous and stays quiet in normal
	// operation.
	DefaultThreshold = 1 * time.Second

	// maxStackBytes caps the goroutine dump. Large enough for the
	// hundreds of goroutines a saturated fetch fan-out produces,
	// bounded so a pathological case cannot allocate without limit.
	maxStackBytes = 4 << 20
)

// Config tunes the watchdog. The zero value is usable: Interval and
// Threshold fall back to their defaults and stacks are dumped.
type Config struct {
	Interval  time.Duration
	Threshold time.Duration

	// NoStacks suppresses the goroutine dump, leaving only the
	// measurement. The dump is what names the code holding the CPU,
	// so leave it on unless log volume is a problem.
	NoStacks bool
}

func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.Threshold <= 0 {
		c.Threshold = DefaultThreshold
	}
	return c
}

// Stall describes one detected stall.
type Stall struct {
	// Overshoot is how much longer than Interval the sleep actually
	// took: the time this process spent unable to run.
	Overshoot time.Duration

	// Elapsed is the full wall time of the window.
	Elapsed time.Duration

	// CPU is process CPU time (user+system, all threads) consumed
	// across the window, and CPUKnown reports whether the platform
	// could supply it.
	CPU      time.Duration
	CPUKnown bool

	// Goroutines is the goroutine count observed after the stall.
	Goroutines int

	// GCCycles is how many GC cycles completed during the window,
	// separating a GC-driven stall from every other kind.
	GCCycles uint32

	// HeapAlloc and HeapSys are heap bytes in use and reserved from
	// the OS, sampled after the stall. A process being reclaimed by
	// the kernel at its cgroup limit shows a large HeapSys.
	HeapAlloc uint64
	HeapSys   uint64
}

// CPUFraction reports CPU time consumed as a fraction of the CPU time
// that was available across the window (Elapsed times GOMAXPROCS).
// Near 0 means the process was not running; near 1 means it was
// saturating its whole CPU budget. Returns -1 when CPU time is not
// available on this platform.
func (s Stall) CPUFraction() float64 {
	if !s.CPUKnown || s.Elapsed <= 0 {
		return -1
	}
	budget := float64(s.Elapsed) * float64(runtime.GOMAXPROCS(0))
	if budget <= 0 {
		return -1
	}
	return float64(s.CPU) / budget
}

// Verdict names what the measurement implies, in the terms the package
// doc lays out. It is deliberately coarse: it points at inside or
// outside the process, and the stack dump does the rest.
func (s Stall) Verdict() string {
	f := s.CPUFraction()
	switch {
	case f < 0:
		return "unknown (no cpu accounting on this platform)"
	case f < 0.15:
		return "descheduled: process got almost no CPU " +
			"(external -- cfs throttling, cgroup reclaim, " +
			"node pressure)"
	case f > 0.75:
		return "cpu-saturated: process consumed its full CPU " +
			"budget (internal -- see goroutine stacks)"
	default:
		return "mixed: partial CPU starvation"
	}
}

// Start runs the watchdog until ctx is cancelled. It returns
// immediately; the loop runs in its own goroutine.
func Start(ctx context.Context, cfg Config) {
	go run(ctx, cfg.withDefaults(), reportStall, realSleep)
}

// sleeper waits for d, reporting false if ctx ended first. It is
// injected so tests can produce a real overshoot deterministically
// rather than trying to starve the scheduler, which is not reliable
// enough to assert on.
type sleeper func(ctx context.Context, d time.Duration) bool

func realSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// run is Start's loop, with the reporting and sleeping functions
// injected so tests can observe detections without parsing logs.
func run(ctx context.Context, cfg Config, report func(Stall),
	sleep sleeper) {

	lastCPU, cpuKnown := processCPUTime()
	lastGC := gcCount()

	for {
		start := time.Now()
		if !sleep(ctx, cfg.Interval) {
			return
		}

		elapsed := time.Since(start)
		nowCPU, nowKnown := processCPUTime()
		nowGC := gcCount()

		cpuDelta := nowCPU - lastCPU
		lastCPU, cpuKnown = nowCPU, nowKnown
		gcDelta := nowGC - lastGC
		lastGC = nowGC

		overshoot := elapsed - cfg.Interval
		if overshoot < cfg.Threshold {
			continue
		}

		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		report(Stall{
			Overshoot:  overshoot,
			Elapsed:    elapsed,
			CPU:        cpuDelta,
			CPUKnown:   cpuKnown,
			Goroutines: runtime.NumGoroutine(),
			GCCycles:   gcDelta,
			HeapAlloc:  ms.HeapAlloc,
			HeapSys:    ms.HeapSys,
		})

		if !cfg.NoStacks {
			slog.Warn("process stall goroutine dump",
				"stacks", goroutineStacks())
		}
	}
}

func reportStall(s Stall) {
	slog.Warn("process stall detected",
		"overshoot", s.Overshoot.String(),
		"window", s.Elapsed.String(),
		"cpu_used", s.CPU.String(),
		"cpu_fraction", s.CPUFraction(),
		"verdict", s.Verdict(),
		"goroutines", s.Goroutines,
		"gc_cycles", s.GCCycles,
		"heap_alloc_mb", s.HeapAlloc>>20,
		"heap_sys_mb", s.HeapSys>>20,
		"gomaxprocs", runtime.GOMAXPROCS(0))
}

func gcCount() uint32 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.NumGC
}

// goroutineStacks returns every goroutine's stack, growing the buffer
// until it fits or the cap is reached.
func goroutineStacks() string {
	size := 64 << 10
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < len(buf) || size >= maxStackBytes {
			return string(buf[:n])
		}
		size *= 2
	}
}

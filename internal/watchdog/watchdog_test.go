package watchdog

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector gathers stalls reported by run.
type collector struct {
	mu     sync.Mutex
	stalls []Stall
	seen   chan struct{}
	once   sync.Once
}

func newCollector() *collector {
	return &collector{seen: make(chan struct{})}
}

func (c *collector) report(s Stall) {
	c.mu.Lock()
	c.stalls = append(c.stalls, s)
	c.mu.Unlock()
	c.once.Do(func() { close(c.seen) })
}

func (c *collector) all() []Stall {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Stall, len(c.stalls))
	copy(out, c.stalls)
	return out
}

func TestNoStallReportedWhenHealthy(t *testing.T) {
	c := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		Interval:  20 * time.Millisecond,
		Threshold: 500 * time.Millisecond,
		NoStacks:  true,
	}
	go run(ctx, cfg, c.report, realSleep)

	time.Sleep(400 * time.Millisecond)
	cancel()

	if got := c.all(); len(got) != 0 {
		t.Errorf("reported %d stalls on a healthy process: %+v",
			len(got), got)
	}
}

// TestStallDetectedWhenSleepOvershoots drives a real overshoot
// through the injected sleeper rather than trying to starve the
// scheduler, which is not reliable enough to assert on. The sleeper
// genuinely sleeps, so the process consumes no CPU across the window
// and the verdict must point outside the process.
func TestStallDetectedWhenSleepOvershoots(t *testing.T) {
	c := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		Interval:  10 * time.Millisecond,
		Threshold: 100 * time.Millisecond,
		NoStacks:  true,
	}
	overshooting := func(ctx context.Context, d time.Duration) bool {
		return realSleep(ctx, d+250*time.Millisecond)
	}
	go run(ctx, cfg, c.report, overshooting)

	select {
	case <-c.seen:
	case <-time.After(10 * time.Second):
		t.Fatal("no stall detected despite a 250ms overshoot")
	}
	cancel()

	for _, s := range c.all() {
		if s.Overshoot < cfg.Threshold {
			t.Errorf("overshoot %v below threshold %v",
				s.Overshoot, cfg.Threshold)
		}
		if s.Elapsed < s.Overshoot {
			t.Errorf("elapsed %v less than overshoot %v",
				s.Elapsed, s.Overshoot)
		}
		if s.Goroutines <= 0 {
			t.Errorf("goroutine count %d", s.Goroutines)
		}
		if v := s.Verdict(); !strings.HasPrefix(v, "descheduled") {
			t.Errorf("verdict %q, want descheduled for an "+
				"idle sleep", v)
		}
	}
}

// TestNoStallWhenOvershootBelowThreshold guards the other direction:
// an overshoot that stays under the threshold must stay silent.
func TestNoStallWhenOvershootBelowThreshold(t *testing.T) {
	c := newCollector()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := Config{
		Interval:  10 * time.Millisecond,
		Threshold: 500 * time.Millisecond,
		NoStacks:  true,
	}
	slightlyLate := func(ctx context.Context, d time.Duration) bool {
		return realSleep(ctx, d+20*time.Millisecond)
	}
	go run(ctx, cfg, c.report, slightlyLate)

	time.Sleep(400 * time.Millisecond)
	cancel()

	if got := c.all(); len(got) != 0 {
		t.Errorf("reported %d stalls for sub-threshold overshoot: %+v",
			len(got), got)
	}
}

func TestCPUFractionNearZeroIsExternal(t *testing.T) {
	s := Stall{
		Elapsed:  10 * time.Second,
		CPU:      50 * time.Millisecond,
		CPUKnown: true,
	}
	if f := s.CPUFraction(); f > 0.15 {
		t.Fatalf("fraction %v, want well under 0.15", f)
	}
	if v := s.Verdict(); !strings.HasPrefix(v, "descheduled") {
		t.Errorf("verdict %q, want descheduled", v)
	}
}

func TestCPUFractionUnknownWhenUnsupported(t *testing.T) {
	s := Stall{Elapsed: time.Second, CPU: 0, CPUKnown: false}
	if f := s.CPUFraction(); f != -1 {
		t.Errorf("fraction %v, want -1", f)
	}
	if v := s.Verdict(); !strings.HasPrefix(v, "unknown") {
		t.Errorf("verdict %q, want unknown", v)
	}
}

func TestCPUFractionZeroElapsedDoesNotDivideByZero(t *testing.T) {
	s := Stall{Elapsed: 0, CPU: time.Second, CPUKnown: true}
	if f := s.CPUFraction(); f != -1 {
		t.Errorf("fraction %v, want -1 for a zero window", f)
	}
}

func TestMixedVerdictBetweenBounds(t *testing.T) {
	s := Stall{
		Elapsed: time.Second,
		CPU: time.Duration(float64(time.Second) * 0.4 *
			float64(runtime.GOMAXPROCS(0))),
		CPUKnown: true,
	}
	if v := s.Verdict(); !strings.HasPrefix(v, "mixed") {
		t.Errorf("verdict %q, want mixed", v)
	}
}

func TestWithDefaultsClampsNonPositive(t *testing.T) {
	for _, in := range []Config{
		{},
		{Interval: -1, Threshold: -1},
		{Interval: 0, Threshold: 0},
	} {
		got := in.withDefaults()
		if got.Interval != DefaultInterval {
			t.Errorf("interval %v, want %v",
				got.Interval, DefaultInterval)
		}
		if got.Threshold != DefaultThreshold {
			t.Errorf("threshold %v, want %v",
				got.Threshold, DefaultThreshold)
		}
	}
}

func TestWithDefaultsKeepsExplicitValues(t *testing.T) {
	in := Config{Interval: 5 * time.Second, Threshold: 2 * time.Second}
	got := in.withDefaults()
	if got.Interval != 5*time.Second ||
		got.Threshold != 2*time.Second {
		t.Errorf("defaults overrode explicit config: %+v", got)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		run(ctx, Config{
			Interval:  10 * time.Millisecond,
			Threshold: time.Second,
			NoStacks:  true,
		}, func(Stall) {}, realSleep)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after context cancel")
	}
}

func TestProcessCPUTimeAdvancesUnderLoad(t *testing.T) {
	before, ok := processCPUTime()
	if !ok {
		t.Skip("no CPU accounting on this platform")
	}
	x := 0
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		for j := 0; j < 100_000; j++ {
			x += j
		}
	}
	_ = x
	after, _ := processCPUTime()
	if after <= before {
		t.Errorf("cpu time did not advance: %v -> %v", before, after)
	}
}

func TestGoroutineStacksIncludesThisTest(t *testing.T) {
	got := goroutineStacks()
	if !strings.Contains(got, "TestGoroutineStacksIncludesThisTest") {
		t.Errorf("dump missing the calling goroutine: %.500s", got)
	}
	if !strings.Contains(got, "goroutine ") {
		t.Errorf("dump does not look like a stack dump: %.200s", got)
	}
}

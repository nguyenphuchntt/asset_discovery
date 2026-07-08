package lifecycle_test

import (
	"context"
	"log/slog"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"passivediscovery/internal/lifecycle"
)

// mockClock controls time in tests.
type mockClock struct {
	now atomic.Pointer[time.Time]
}

func (m *mockClock) Now() time.Time {
	if v := m.now.Load(); v != nil {
		return *v
	}
	return time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
}

func (m *mockClock) Set(t time.Time) { m.now.Store(&t) }

// stubManager records calls to Sweep and EvictStale.
type stubManager struct {
	sweepCalls      atomic.Int64
	sweepCount      atomic.Int64 // total returned by Sweep
	evictCalls      atomic.Int64
	evictCount      atomic.Int64 // total returned by EvictStale
	lastSweepNow    time.Time
	lastSweepOA     time.Duration
	lastEvictNow    time.Time
	lastEvictEA     time.Duration
}

func (m *stubManager) Sweep(now time.Time, offlineAfter time.Duration) int {
	m.sweepCalls.Add(1)
	m.lastSweepNow = now
	m.lastSweepOA = offlineAfter
	return int(m.sweepCount.Load())
}
func (m *stubManager) EvictStale(now time.Time, evictAfter time.Duration) int {
	m.evictCalls.Add(1)
	m.lastEvictNow = now
	m.lastEvictEA = evictAfter
	return int(m.evictCount.Load())
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------- NewTracker ----------

func TestNewTracker_NilClock(t *testing.T) {
	mgr := &stubManager{}
	trk := lifecycle.NewTracker(mgr, nil, time.Second, time.Minute, time.Hour, discardLogger())
	if trk == nil {
		t.Fatal("expected non-nil tracker")
	}
}

func TestNewTracker_NilLogger(t *testing.T) {
	mgr := &stubManager{}
	trk := lifecycle.NewTracker(mgr, &mockClock{}, time.Second, time.Minute, time.Hour, nil)
	if trk == nil {
		t.Fatal("expected non-nil tracker")
	}
}

// ---------- Tracker.Run ----------

func TestTracker_Run_ContextCancel(t *testing.T) {
	mgr := &stubManager{}
	clk := &mockClock{}
	trk := lifecycle.NewTracker(mgr, clk, time.Second, time.Minute, time.Hour, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- trk.Run(ctx) }()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after context cancel")
	}
}

func TestTracker_Run_CallsSweepAndEvict(t *testing.T) {
	mgr := &stubManager{}
	clk := &mockClock{}
	trk := lifecycle.NewTracker(mgr, clk, 50*time.Millisecond, time.Minute, time.Hour, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go trk.Run(ctx)

	// wait for at least 2 ticks
	time.Sleep(130 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond) // let Run return

	if n := mgr.sweepCalls.Load(); n < 2 {
		t.Errorf("expected at least 2 Sweep calls, got %d", n)
	}
	if n := mgr.evictCalls.Load(); n < 2 {
		t.Errorf("expected at least 2 EvictStale calls, got %d", n)
	}
}

func TestTracker_Run_PassesCorrectArgs(t *testing.T) {
	mgr := &stubManager{}
	clk := &mockClock{}
	fixed := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	clk.Set(fixed)

	trk := lifecycle.NewTracker(mgr, clk, 50*time.Millisecond, 5*time.Minute, 24*time.Hour, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go trk.Run(ctx)

	time.Sleep(80 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	if mgr.lastSweepOA != 5*time.Minute {
		t.Errorf("Sweep offlineAfter: want 5m, got %v", mgr.lastSweepOA)
	}
	if mgr.lastEvictEA != 24*time.Hour {
		t.Errorf("EvictStale evictAfter: want 24h, got %v", mgr.lastEvictEA)
	}
}

func TestTracker_Run_WithSweepReturningCount(t *testing.T) {
	mgr := &stubManager{}
	mgr.sweepCount.Store(3)
	clk := &mockClock{}
	trk := lifecycle.NewTracker(mgr, clk, 50*time.Millisecond, time.Minute, time.Hour, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go trk.Run(ctx)

	time.Sleep(80 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	// No panic, no error — Sweep returned 3, tracker logged it
	if mgr.sweepCalls.Load() < 1 {
		t.Error("expected at least 1 Sweep call")
	}
}

func TestTracker_Run_EvictReturningCount(t *testing.T) {
	mgr := &stubManager{}
	mgr.evictCount.Store(5)
	clk := &mockClock{}
	trk := lifecycle.NewTracker(mgr, clk, 50*time.Millisecond, time.Minute, time.Hour, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	go trk.Run(ctx)

	time.Sleep(80 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	if mgr.evictCalls.Load() < 1 {
		t.Error("expected at least 1 EvictStale call")
	}
}

// ---------- RealClock ----------

func TestRealClock_Now(t *testing.T) {
	var clk lifecycle.RealClock
	before := time.Now()
	got := clk.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("RealClock.Now() = %v not between %v and %v", got, before, after)
	}
}

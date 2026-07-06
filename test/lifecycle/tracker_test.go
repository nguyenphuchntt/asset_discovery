package lifecycle_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/lifecycle"
)

// fakeManager implements the lifecycle.Manager interface for testing.
type fakeManager struct {
	sweepCalls  atomic.Int32
	evictCalls  atomic.Int32
	lastEvicted atomic.Int32
}

func (f *fakeManager) Sweep(_ time.Time, _ time.Duration) []asset.Event {
	f.sweepCalls.Add(1)
	return nil
}

func (f *fakeManager) EvictStale(_ time.Time, _ time.Duration) int {
	f.evictCalls.Add(1)
	return int(f.lastEvicted.Load())
}

func TestTracker_RunTicksAtInterval(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	tr := lifecycle.NewTracker(mgr, lifecycle.RealClock{}, 20*time.Millisecond, time.Hour, 0, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	go tr.Run(ctx)

	time.Sleep(100 * time.Millisecond)
	cancel()

	if got := mgr.sweepCalls.Load(); got < 3 {
		t.Errorf("expected at least 3 sweep calls in 100ms with 20ms interval, got %d", got)
	}
}

func TestTracker_RunStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	tr := lifecycle.NewTracker(mgr, lifecycle.RealClock{}, 10*time.Millisecond, time.Hour, 0, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s after cancel")
	}
}

func TestTracker_RunReturnsNilOnCleanShutdown(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	tr := lifecycle.NewTracker(mgr, lifecycle.RealClock{}, 100*time.Millisecond, time.Hour, 0, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return")
	}
}

func TestRealClock_Now(t *testing.T) {
	t.Parallel()
	var c lifecycle.Clock = lifecycle.RealClock{}
	before := time.Now()
	got := c.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("RealClock.Now() out of range: %v not in [%v, %v]", got, before, after)
	}
}

// fakeClock implements lifecycle.Clock for testing deterministic time.
type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) Advance(d time.Duration) { f.now = f.now.Add(d) }

func TestFakeClock_Advance(t *testing.T) {
	t.Parallel()
	c := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c.Advance(time.Hour)

	expected := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	if !c.Now().Equal(expected) {
		t.Errorf("expected %v, got %v", expected, c.Now())
	}
}
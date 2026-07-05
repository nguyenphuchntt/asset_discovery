package stats_test

import (
	"context"
	"testing"
	"time"

	"passivediscovery/internal/stats"
)

// Collector — covered scenarios:
//   1. Snapshot with nil persister → flush counters zero
//   2. Snapshot with persister → counters populated from persister
//   3. RunCounts fields preserved in snapshot
//   4. CapturedAt is set to current time
//   5. KernelDropped, InternalDropped copied through

type fakePersister struct {
	flushCount  uint64
	flushErrors uint64
	lastFlush   time.Duration
}

func (f *fakePersister) Counters() (uint64, uint64, time.Duration) {
	return f.flushCount, f.flushErrors, f.lastFlush
}

func TestCollector_SnapshotNilPersister(t *testing.T) {
	t.Parallel()
	c := stats.NewCollector(nil)
	snap := c.Snapshot(context.Background(), stats.RunCounts{
		RunID:            "run_1",
		PacketsReceived:  100,
		Observations:     50,
		InternalDropped:  5,
	})

	if snap.RunID != "run_1" {
		t.Errorf("expected RunID=run_1, got %q", snap.RunID)
	}
	if snap.PacketsReceived != 100 {
		t.Errorf("expected PacketsReceived=100, got %d", snap.PacketsReceived)
	}
	if snap.DBFlushCount != 0 {
		t.Errorf("expected DBFlushCount=0 with nil persister, got %d", snap.DBFlushCount)
	}
}

func TestCollector_SnapshotWithPersister(t *testing.T) {
	t.Parallel()
	p := &fakePersister{flushCount: 10, flushErrors: 2, lastFlush: 50 * time.Millisecond}
	c := stats.NewCollector(p)

	snap := c.Snapshot(context.Background(), stats.RunCounts{RunID: "run_2"})

	if snap.DBFlushCount != 10 {
		t.Errorf("expected DBFlushCount=10, got %d", snap.DBFlushCount)
	}
	if snap.DBFlushErrors != 2 {
		t.Errorf("expected DBFlushErrors=2, got %d", snap.DBFlushErrors)
	}
	if snap.DBFlushLast != 50*time.Millisecond {
		t.Errorf("expected DBFlushLast=50ms, got %v", snap.DBFlushLast)
	}
}

func TestCollector_CapturedAtSet(t *testing.T) {
	t.Parallel()
	c := stats.NewCollector(nil)
	before := time.Now()
	snap := c.Snapshot(context.Background(), stats.RunCounts{})
	after := time.Now()

	if snap.CapturedAt.Before(before) || snap.CapturedAt.After(after) {
		t.Errorf("CaptainedAt out of range: %v not in [%v, %v]", snap.CapturedAt, before, after)
	}
}

func TestCollector_RunCountsPreserved(t *testing.T) {
	t.Parallel()
	c := stats.NewCollector(nil)
	snap := c.Snapshot(context.Background(), stats.RunCounts{
		PacketsReceived:   1000,
		Observations:      500,
		KernelDropped:     3,
		InternalDropped:   7,
		RawQueueDepth:     100,
		PersistQueueDepth: 20,
	})

	if snap.PacketsReceived != 1000 {
		t.Errorf("expected PacketsReceived=1000, got %d", snap.PacketsReceived)
	}
	if snap.KernelDropped != 3 {
		t.Errorf("expected KernelDropped=3, got %d", snap.KernelDropped)
	}
	if snap.RawQueueDepth != 100 {
		t.Errorf("expected RawQueueDepth=100, got %d", snap.RawQueueDepth)
	}
}

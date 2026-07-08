package stats_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"passivediscovery/internal/stats"
	"passivediscovery/internal/storage"
)

// ---------- helpers ----------

type stubPersister struct {
	flushCount uint64
	flushErrors uint64
	lastFlush  time.Duration
}

func (s *stubPersister) Counters() (uint64, uint64, time.Duration) {
	return s.flushCount, s.flushErrors, s.lastFlush
}

func TestCounters_ZeroValue(t *testing.T) {
	c := stats.Counters{}
	if c.PacketsReceived != 0 { t.Errorf("expected 0, got %d", c.PacketsReceived) }
	if c.Observations    != 0 { t.Errorf("expected 0, got %d", c.Observations) }
	if c.AssetsCreated   != 0 { t.Errorf("expected 0, got %d", c.AssetsCreated) }
	if c.AssetsUpdated   != 0 { t.Errorf("expected 0, got %d", c.AssetsUpdated) }
	if c.KernelDropped   != 0 { t.Errorf("expected 0, got %d", c.KernelDropped) }
	if c.InternalDropped != 0 { t.Errorf("expected 0, got %d", c.InternalDropped) }
	if c.DBFlushCount    != 0 { t.Errorf("expected 0, got %d", c.DBFlushCount) }
	if c.DBFlushErrors   != 0 { t.Errorf("expected 0, got %d", c.DBFlushErrors) }
	if c.DBFlushLast     != 0 { t.Errorf("expected 0, got %v", c.DBFlushLast) }
}

func TestCounters_FieldsSettable(t *testing.T) {
	c := stats.Counters{
		PacketsReceived: 1000,
		Observations:    80,
		AssetsCreated:   2,
		AssetsUpdated:   5,
		KernelDropped:   10,
		InternalDropped: 3,
		DBFlushCount:    20,
		DBFlushErrors:   1,
		DBFlushLast:     50 * time.Millisecond,
	}
	if c.PacketsReceived != 1000       { t.Errorf("PacketsReceived: want 1000, got %d", c.PacketsReceived) }
	if c.Observations    != 80          { t.Errorf("Observations: want 80, got %d", c.Observations) }
	if c.AssetsCreated   != 2           { t.Errorf("AssetsCreated: want 2, got %d", c.AssetsCreated) }
	if c.AssetsUpdated   != 5           { t.Errorf("AssetsUpdated: want 5, got %d", c.AssetsUpdated) }
	if c.KernelDropped   != 10          { t.Errorf("KernelDropped: want 10, got %d", c.KernelDropped) }
	if c.InternalDropped != 3           { t.Errorf("InternalDropped: want 3, got %d", c.InternalDropped) }
	if c.DBFlushCount    != 20          { t.Errorf("DBFlushCount: want 20, got %d", c.DBFlushCount) }
	if c.DBFlushErrors   != 1           { t.Errorf("DBFlushErrors: want 1, got %d", c.DBFlushErrors) }
	if c.DBFlushLast     != 50*time.Millisecond { t.Errorf("DBFlushLast: want 50ms, got %v", c.DBFlushLast) }
}

func TestCounters_JSON(t *testing.T) {
	c := stats.Counters{
		PacketsReceived: 100,
		Observations:    10,
		DBFlushLast:     5 * time.Millisecond,
	}
	b, err := json.Marshal(c)
	if err != nil { t.Fatalf("marshal: %v", err) }
	var got stats.Counters
	if err := json.Unmarshal(b, &got); err != nil { t.Fatalf("unmarshal: %v", err) }
	if got.PacketsReceived != 100         { t.Errorf("roundtrip PacketsReceived: want 100, got %d", got.PacketsReceived) }
	if got.Observations    != 10          { t.Errorf("roundtrip Observations: want 10, got %d", got.Observations) }
	if got.DBFlushLast     != 5*time.Millisecond { t.Errorf("roundtrip DBFlushLast: want 5ms, got %v", got.DBFlushLast) }
}

func TestCounters_JSONTagKeys(t *testing.T) {
	c := stats.Counters{PacketsReceived: 1}
	b, _ := json.Marshal(c)
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil { t.Fatalf("unmarshal: %v", err) }
	if _, ok := raw["packets_received"]; !ok { t.Error("expected key packets_received in JSON output") }
}

// ---------- Collector ----------

func TestNewCollector_Nil(t *testing.T) {
	// nil persister is allowed
	c := stats.NewCollector(nil)
	if c == nil { t.Fatal("expected non-nil Collector") }
}

func TestNewCollector_WithPersister(t *testing.T) {
	p := &stubPersister{flushCount: 5, flushErrors: 2, lastFlush: 10 * time.Millisecond}
	c := stats.NewCollector(p)
	if c == nil { t.Fatal("expected non-nil Collector") }
}

func TestSnapshot_NilPersister(t *testing.T) {
	c := stats.NewCollector(nil)
	run := stats.RunCounts{
		RunID:           "run-1",
		PacketsReceived: 1000,
		Observations:    50,
		AssetsCreated:   3,
		AssetsUpdated:   7,
		KernelDropped:   10,
		InternalDropped: 2,
		RawQueueDepth:   128,
		PersistQueueDepth: 64,
	}
	snap := c.Snapshot(context.Background(), run)
	if snap.RunID            != "run-1"    { t.Errorf("RunID: want run-1, got %s", snap.RunID) }
	if snap.PacketsReceived  != 1000       { t.Errorf("PacketsReceived: want 1000, got %d", snap.PacketsReceived) }
	if snap.Observations     != 50         { t.Errorf("Observations: want 50, got %d", snap.Observations) }
	if snap.AssetsCreated    != 3          { t.Errorf("AssetsCreated: want 3, got %d", snap.AssetsCreated) }
	if snap.AssetsUpdated    != 7          { t.Errorf("AssetsUpdated: want 7, got %d", snap.AssetsUpdated) }
	if snap.KernelDropped    != 10         { t.Errorf("KernelDropped: want 10, got %d", snap.KernelDropped) }
	if snap.InternalDropped  != 2          { t.Errorf("InternalDropped: want 2, got %d", snap.InternalDropped) }
	if snap.RawQueueDepth    != 128        { t.Errorf("RawQueueDepth: want 128, got %d", snap.RawQueueDepth) }
	if snap.PersistQueueDepth != 64        { t.Errorf("PersistQueueDepth: want 64, got %d", snap.PersistQueueDepth) }
	if snap.DBFlushCount     != 0          { t.Errorf("DBFlushCount: want 0, got %d", snap.DBFlushCount) }
	if snap.DBFlushErrors    != 0          { t.Errorf("DBFlushErrors: want 0, got %d", snap.DBFlushErrors) }
	if snap.DBFlushLast      != 0          { t.Errorf("DBFlushLast: want 0, got %v", snap.DBFlushLast) }
}

func TestSnapshot_NilPersister_Zeros(t *testing.T) {
	c := stats.NewCollector(nil)
	snap := c.Snapshot(context.Background(), stats.RunCounts{})
	if snap.DBFlushCount != 0 || snap.DBFlushErrors != 0 || snap.DBFlushLast != 0 {
		t.Errorf("expected all persister stats to be zero when persister is nil, got flush=%d errors=%d last=%v",
			snap.DBFlushCount, snap.DBFlushErrors, snap.DBFlushLast)
	}
}

func TestSnapshot_WithPersister(t *testing.T) {
	p := &stubPersister{flushCount: 50, flushErrors: 3, lastFlush: 120 * time.Millisecond}
	c := stats.NewCollector(p)
	run := stats.RunCounts{
		RunID:            "run-42",
		PacketsReceived:  2000,
		Observations:     200,
		AssetsCreated:    10,
		AssetsUpdated:    25,
		KernelDropped:    5,
		InternalDropped:  1,
		RawQueueDepth:    64,
		PersistQueueDepth: 32,
	}
	snap := c.Snapshot(context.Background(), run)
	if snap.DBFlushCount  != 50           { t.Errorf("DBFlushCount: want 50, got %d", snap.DBFlushCount) }
	if snap.DBFlushErrors != 3            { t.Errorf("DBFlushErrors: want 3, got %d", snap.DBFlushErrors) }
	if snap.DBFlushLast   != 120*time.Millisecond { t.Errorf("DBFlushLast: want 120ms, got %v", snap.DBFlushLast) }
	if snap.RunID         != "run-42"     { t.Errorf("RunID: want run-42, got %s", snap.RunID) }
	if snap.PacketsReceived != 2000       { t.Errorf("PacketsReceived: want 2000, got %d", snap.PacketsReceived) }
	if snap.Observations    != 200        { t.Errorf("Observations: want 200, got %d", snap.Observations) }
}

func TestSnapshot_CapturedAt_Timestamp(t *testing.T) {
	c := stats.NewCollector(nil)
	before := time.Now().UTC()
	snap := c.Snapshot(context.Background(), stats.RunCounts{})
	after := time.Now().UTC()
	if snap.CapturedAt.Before(before) || snap.CapturedAt.After(after) {
		t.Errorf("CapturedAt %v not between %v and %v", snap.CapturedAt, before, after)
	}
}

func TestSnapshot_RoundTripJSON(t *testing.T) {
	p := &stubPersister{flushCount: 5, flushErrors: 1, lastFlush: 8 * time.Millisecond}
	c := stats.NewCollector(p)
	run := stats.RunCounts{
		RunID:            "rt-1",
		PacketsReceived:  100,
		Observations:     20,
		AssetsCreated:    2,
		AssetsUpdated:    3,
		KernelDropped:    0,
		InternalDropped:  1,
		RawQueueDepth:    16,
		PersistQueueDepth: 8,
	}
	snap := c.Snapshot(context.Background(), run)
	b, err := json.Marshal(snap)
	if err != nil { t.Fatalf("marshal: %v", err) }
	var got storage.StatsSnapshot
	if err := json.Unmarshal(b, &got); err != nil { t.Fatalf("unmarshal: %v", err) }
	if got.RunID            != snap.RunID            { t.Errorf("RunID mismatch") }
	if got.PacketsReceived  != snap.PacketsReceived  { t.Errorf("PacketsReceived mismatch") }
	if got.DBFlushCount     != snap.DBFlushCount     { t.Errorf("DBFlushCount mismatch") }
	if got.DBFlushLast      != snap.DBFlushLast      { t.Errorf("DBFlushLast mismatch") }
}

func TestSnapshot_EmptyRunCounts(t *testing.T) {
	c := stats.NewCollector(nil)
	snap := c.Snapshot(context.Background(), stats.RunCounts{})
	if snap.PacketsReceived  != 0 { t.Errorf("expected 0 PacketsReceived, got %d", snap.PacketsReceived) }
	if snap.Observations     != 0 { t.Errorf("expected 0 Observations, got %d", snap.Observations) }
	if snap.RawQueueDepth    != 0 { t.Errorf("expected 0 RawQueueDepth, got %d", snap.RawQueueDepth) }
	if snap.PersistQueueDepth != 0 { t.Errorf("expected 0 PersistQueueDepth, got %d", snap.PersistQueueDepth) }
}

func TestSnapshot_ContextUnused(t *testing.T) {
	// context is unused in Snapshot; verify different contexts don't change output
	c := stats.NewCollector(nil)
	run := stats.RunCounts{RunID: "ctx-test", PacketsReceived: 42}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	s1 := c.Snapshot(ctx1, run)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel2()
	time.Sleep(2 * time.Millisecond)
	s2 := c.Snapshot(ctx2, run)
	if s1.PacketsReceived != s2.PacketsReceived {
		t.Errorf("context should not affect snapshot, got %d vs %d", s1.PacketsReceived, s2.PacketsReceived)
	}
}

// ---------- Concurrent ----------

func TestSnapshot_ConcurrentReads(t *testing.T) {
	p := &stubPersister{flushCount: 10, flushErrors: 0, lastFlush: 5 * time.Millisecond}
	c := stats.NewCollector(p)
	run := stats.RunCounts{RunID: "concurrent", PacketsReceived: 500}
	errc := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func() {
			snap := c.Snapshot(context.Background(), run)
			if snap.RunID != "concurrent" { errc <- errDifferentRunID; return }
			errc <- nil
		}()
	}
	for i := 0; i < 50; i++ {
		if err := <-errc; err != nil { t.Errorf("goroutine %d: %v", i, err) }
	}
}

type errSentinel struct {
	reason string
}

func (e errSentinel) Error() string { return e.reason }

var errDifferentRunID = errSentinel{"RunID mismatch in concurrent snapshot"}

// ---------- StatsSnapshot fields ----------

func TestStatsSnapshot_AllFieldsPresent(t *testing.T) {
	snap := storage.StatsSnapshot{
		RunID:              "all-fields",
		PacketsReceived:    1000,
		Observations:       500,
		AssetsCreated:      10,
		AssetsUpdated:      20,
		KernelDropped:      5,
		InternalDropped:    3,
		RawQueueDepth:      256,
		PersistQueueDepth:  128,
		DBFlushCount:       30,
		DBFlushErrors:      2,
		DBFlushLast:        42 * time.Millisecond,
	}
	b, err := json.Marshal(snap)
	if err != nil { t.Fatalf("marshal: %v", err) }
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil { t.Fatalf("unmarshal: %v", err) }
	expectedKeys := []string{
		"RunID", "PacketsReceived", "Observations",
		"AssetsCreated", "AssetsUpdated",
		"KernelDropped", "InternalDropped",
		"RawQueueDepth", "PersistQueueDepth",
		"DBFlushCount", "DBFlushErrors", "DBFlushLast",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON output missing expected key: %s", key)
		}
	}
}

func TestStatsSnapshot_ZeroValue(t *testing.T) {
	s := storage.StatsSnapshot{}
	if s.RunID != "" { t.Errorf("expected empty RunID, got %s", s.RunID) }
	if s.PacketsReceived != 0 { t.Errorf("expected 0, got %d", s.PacketsReceived) }
	if s.DBFlushLast != 0 { t.Errorf("expected 0 duration, got %v", s.DBFlushLast) }
}

// ---------- NewCollector edge cases ----------

func TestNewCollector_NilPersister_SnapshotSnapshot(t *testing.T) {
	// ensure we can call Snapshot multiple times on nil-persister collector
	c := stats.NewCollector(nil)
	for i := 0; i < 100; i++ {
		snap := c.Snapshot(context.Background(), stats.RunCounts{PacketsReceived: uint64(i)})
		if snap.DBFlushCount != 0 {
			t.Fatalf("iteration %d: expected DBFlushCount 0, got %d", i, snap.DBFlushCount)
		}
	}
}

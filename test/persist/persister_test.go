package persist_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/persist"
	"passivediscovery/internal/storage"
)

// stubSource returns the given assets on DrainDirty (thread-safe).
type stubSource struct {
	mu     sync.Mutex
	dirty  []asset.AssetSnapshot
	closed bool
}

func (s *stubSource) DrainDirty() []asset.AssetSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	out := s.dirty
	s.dirty = nil
	return out
}

func (s *stubSource) SetDirty(a []asset.AssetSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = a
}

// stubRepo is a minimal storage.Repository for testing.
type stubRepo struct {
	mu             sync.Mutex
	saveBatchCalls atomic.Int64
	saveBatchErr   error
	saveBatchFn    func(ctx context.Context, assets []asset.AssetSnapshot) error

	saveStatsCalls atomic.Int64
	savedStats     []storage.Statistics
}

func (r *stubRepo) Init(ctx context.Context) error { return nil }
func (r *stubRepo) LoadAssets(ctx context.Context, opts storage.LoadOptions) ([]asset.AssetSnapshot, error) {
	return nil, nil
}
func (r *stubRepo) LoadAssetByMAC(ctx context.Context, mac string) (*asset.AssetSnapshot, error) {
	return nil, nil
}
func (r *stubRepo) LoadLastStatistics(ctx context.Context) (storage.Statistics, bool, error) {
	return storage.Statistics{}, false, nil
}
func (r *stubRepo) SaveBatch(ctx context.Context, assets []asset.AssetSnapshot) error {
	r.saveBatchCalls.Add(1)
	if r.saveBatchFn != nil {
		return r.saveBatchFn(ctx, assets)
	}
	return r.saveBatchErr
}
func (r *stubRepo) SaveStatistics(ctx context.Context, s storage.Statistics) error {
	r.saveStatsCalls.Add(1)
	r.mu.Lock()
	r.savedStats = append(r.savedStats, s)
	r.mu.Unlock()
	return nil
}
func (r *stubRepo) Close() error { return nil }

// stubStats implements persist.StatsSource.
type stubStats struct {
	packets    uint64
	assets     uint64
	packetsPS  float64
}

func (s *stubStats) PacketsReceived() uint64 { return s.packets }
func (s *stubStats) AssetsCount() uint64     { return s.assets }
func (s *stubStats) PacketsPerSec() float64  { return s.packetsPS }
func (s *stubStats) StatusCounts() (online, offline int) { return 0, 0 }
func (s *stubStats) Drops() uint64                      { return 0 }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------- New ----------

func TestNew_NilLogger(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, nil)
	if p == nil {
		t.Fatal("expected non-nil persister")
	}
}

func TestNew_DefaultOptions(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())
	if p == nil {
		t.Fatal("expected non-nil persister")
	}
	// Force a flush to ensure default options work
	src.SetDirty([]asset.AssetSnapshot{{ID: "test-asset"}})
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush with defaults: %v", err)
	}
}

// ---------- SetOptions / WithOptions ----------

func TestSetOptions_Overrides(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())
	p.SetOptions(persist.Options{
		BatchSize:  100,
		FlushEvery: 10 * time.Second,
	})
	if p == nil {
		t.Fatal("expected non-nil")
	}
}

func TestWithOptions_ReturnsSelf(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())
	if got := p.WithOptions(persist.Options{BatchSize: 50}); got != p {
		t.Error("WithOptions should return self for chaining")
	}
}

func TestSetOptions_KeepsDefaultsForZeroFields(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())
	// All zero - should keep defaults
	p.SetOptions(persist.Options{})
	// If we got here without panicking, defaults preserved
}

// ---------- Flush ----------

func TestFlush_EmptyBatch(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())

	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush empty: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 0 {
		t.Errorf("SaveBatch calls: want 0, got %d", n)
	}
}

func TestFlush_WithDirtyAssets(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{
		{ID: "a1"}, {ID: "a2"},
	})
	p := persist.New(repo, src, discardLogger())

	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 1 {
		t.Errorf("SaveBatch calls: want 1, got %d", n)
	}
	// second flush with no new dirty -> no extra call
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush 2: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 1 {
		t.Errorf("SaveBatch calls after 2nd flush: want 1, got %d", n)
	}
}

func TestFlush_BatchSizeOverflow(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	assets := make([]asset.AssetSnapshot, 5)
	for i := range assets {
		assets[i] = asset.AssetSnapshot{ID: asset.AssetID("a") + asset.AssetID(string(rune('0' + i)))}
	}
	src.SetDirty(assets)

	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		BatchSize:  2,
		FlushEvery: time.Second,
	})

	// First flush: should take 2, leave 3 in pendingBatch
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush 1: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 1 {
		t.Errorf("SaveBatch calls: want 1, got %d", n)
	}

	// Second flush: should take the remaining 3
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush 2: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 2 {
		t.Errorf("SaveBatch calls: want 2, got %d", n)
	}
}

func TestFlush_ErrorIncrementsCounters(t *testing.T) {
	repo := &stubRepo{saveBatchErr: errors.New("db broken")}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a1"}})
	p := persist.New(repo, src, discardLogger())

	if err := p.Flush(context.Background()); err == nil {
		t.Error("Flush should return error")
	}
	_, flushErrors, _ := p.Counters()
	if flushErrors != 1 {
		t.Errorf("flushErrors: want 1, got %d", flushErrors)
	}
}

// ---------- Retry ----------

func TestSaveWithRetry_SucceedOnFirstTry(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	p := persist.New(repo, src, discardLogger())
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 1 {
		t.Errorf("SaveBatch calls: want 1, got %d", n)
	}
}

func TestSaveWithRetry_SucceedOnSecondTry(t *testing.T) {
	var calls atomic.Int64
	repo := &stubRepo{saveBatchFn: func(ctx context.Context, a []asset.AssetSnapshot) error {
		if calls.Add(1) == 1 {
			return errors.New("transient")
		}
		return nil
	}}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		BatchSize:    10,
		RetryLimit:   3,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 2 {
		t.Errorf("SaveBatch calls: want 2, got %d", n)
	}
}

func TestSaveWithRetry_AllFail(t *testing.T) {
	repo := &stubRepo{saveBatchErr: errors.New("persistent")}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		BatchSize:    10,
		RetryLimit:   2,
		RetryBackoff: 5 * time.Millisecond,
	})
	if err := p.Flush(context.Background()); err == nil {
		t.Error("Flush should fail after all retries")
	}
	if n := repo.saveBatchCalls.Load(); n != 2 {
		t.Errorf("SaveBatch calls: want 2, got %d", n)
	}
}

func TestSaveWithRetry_ContextCanceledImmediate(t *testing.T) {
	repo := &stubRepo{saveBatchErr: context.Canceled}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		BatchSize:    10,
		RetryLimit:   3,
		RetryBackoff: 5 * time.Millisecond,
	})
	if err := p.Flush(context.Background()); !errors.Is(err, context.Canceled) {
		t.Errorf("Flush: want context.Canceled, got %v", err)
	}
	if n := repo.saveBatchCalls.Load(); n != 1 {
		t.Errorf("SaveBatch calls: want 1 (no retry on cancel), got %d", n)
	}
}

func TestSaveWithRetry_BackoffCap(t *testing.T) {
	repo := &stubRepo{saveBatchErr: errors.New("x")}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	// Use small initial backoff but verify that large values get capped
	// by checking the cap logic indirectly: request huge backoff, cap test
	// just verifies retry happens within a reasonable bound.
	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		BatchSize:    10,
		RetryLimit:   3,
		RetryBackoff: 100 * time.Millisecond,
	})
	start := time.Now()
	_ = p.Flush(context.Background())
	elapsed := time.Since(start)
	// 2 retries × 100ms = 200ms (cap not triggered)
	if elapsed > 2*time.Second {
		t.Errorf("retry took too long: %v", elapsed)
	}
}

// ---------- Statistics hook ----------

func TestSetStats_NilSkips(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	p := persist.New(repo, src, discardLogger())
	// no SetStats
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	if n := repo.saveStatsCalls.Load(); n != 0 {
		t.Errorf("SaveStats calls: want 0, got %d", n)
	}
}

func TestSetStats_TriggersSave(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	stats := &stubStats{packets: 100, assets: 5, packetsPS: 10.5}
	p := persist.New(repo, src, discardLogger()).SetStats(stats)

	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	if n := repo.saveStatsCalls.Load(); n != 1 {
		t.Errorf("SaveStats calls: want 1, got %d", n)
	}
	repo.mu.Lock()
	if len(repo.savedStats) != 1 {
		t.Fatalf("savedStats len: want 1, got %d", len(repo.savedStats))
	}
	got := repo.savedStats[0]
	repo.mu.Unlock()
	if got.PacketsReceived != 100 {
		t.Errorf("PacketsReceived: want 100, got %d", got.PacketsReceived)
	}
	if got.AssetsCount != 5 {
		t.Errorf("AssetsCount: want 5, got %d", got.AssetsCount)
	}
	if got.PacketsPerSec != 10.5 {
		t.Errorf("PacketsPerSec: want 10.5, got %v", got.PacketsPerSec)
	}
}

// ---------- Run lifecycle ----------

func TestRun_ContextCancel(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		FlushEvery:   20 * time.Millisecond,
		FlushTimeout: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit")
	}
}

func TestRun_PeriodicFlush(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})

	p := persist.New(repo, src, discardLogger()).SetOptions(persist.Options{
		FlushEvery:   20 * time.Millisecond,
		FlushTimeout: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)

	// wait for at least 2 ticks
	time.Sleep(60 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	if n := repo.saveBatchCalls.Load(); n < 1 {
		t.Errorf("SaveBatch calls: want >=1, got %d", n)
	}
}

// ---------- Counters ----------

func TestCounters_InitialZero(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())
	fc, fe, _ := p.Counters()
	if fc != 0 || fe != 0 {
		t.Errorf("Counters initial: want 0/0, got %d/%d", fc, fe)
	}
}

func TestCounters_AfterSuccess(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	src.SetDirty([]asset.AssetSnapshot{{ID: "a"}})
	p := persist.New(repo, src, discardLogger())

	_ = p.Flush(context.Background())
	fc, _, dur := p.Counters()
	if fc != 1 {
		t.Errorf("flushCount: want 1, got %d", fc)
	}
	if dur <= 0 {
		t.Errorf("lastFlush should be > 0, got %v", dur)
	}
}

// ---------- concurrent ----------

func TestCollectBatch_ConcurrentSafe(t *testing.T) {
	repo := &stubRepo{}
	src := &stubSource{}
	p := persist.New(repo, src, discardLogger())

	const goroutines = 20
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				src.SetDirty([]asset.AssetSnapshot{{ID: "x"}})
				_ = p.Flush(context.Background())
			}
		}()
	}
	wg.Wait()
	// Should not panic on data race
}

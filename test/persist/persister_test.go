package persist_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/persist"
	"passivediscovery/internal/storage"
)

// fakeSource implements persist.Source for tests.
type fakeSource struct {
	snapshots []asset.AssetSnapshot
	dirtyCalls atomic.Int32
}

func (s *fakeSource) DrainDirty() []asset.AssetSnapshot {
	s.dirtyCalls.Add(1)
	out := s.snapshots
	s.snapshots = nil
	return out
}

// fakeRepo implements storage.Repository. Only SaveBatch is exercised here.
type fakeRepo struct {
	storage.Repository
	saveErr        error
	saveCallCount  atomic.Int32
	savedBatches   []storage.Batch
	failNextN      atomic.Int32
}

func (r *fakeRepo) SaveBatch(_ context.Context, b storage.Batch) error {
	r.saveCallCount.Add(1)
	r.savedBatches = append(r.savedBatches, b)
	if r.failNextN.Load() > 0 {
		r.failNextN.Add(-1)
		return r.saveErr
	}
	return nil
}

func (r *fakeRepo) Close() error { return nil }

func TestPersister_FlushEmptyBatchNoop(t *testing.T) {
	t.Parallel()
	src := &fakeSource{}
	repo := &fakeRepo{}
	p := persist.New(repo, src, "run_1", slog.Default())

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("Flush should succeed on empty batch: %v", err)
	}
	if repo.saveCallCount.Load() != 0 {
		t.Errorf("expected 0 save calls, got %d", repo.saveCallCount.Load())
	}
}

func TestPersister_FlushSavesBatch(t *testing.T) {
	t.Parallel()
	src := &fakeSource{
		snapshots: []asset.AssetSnapshot{
			{ID: "mac:aa:bb:cc:dd:ee:01", MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"), Status: asset.StatusOnline},
		},
	}
	repo := &fakeRepo{}
	p := persist.New(repo, src, "run_2", slog.Default())

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if repo.saveCallCount.Load() != 1 {
		t.Errorf("expected 1 save call, got %d", repo.saveCallCount.Load())
	}
}

func TestPersister_FlushRetriesOnError(t *testing.T) {
	t.Parallel()
	src := &fakeSource{
		snapshots: []asset.AssetSnapshot{{ID: "mac:aa:bb:cc:dd:ee:01", Status: asset.StatusOnline}},
	}
	repo := &fakeRepo{saveErr: errors.New("transient")}
	repo.failNextN.Store(2)

	p := persist.New(repo, src, "run_3", slog.Default()).SetOptions(persist.Options{
		BatchSize: 10, FlushEvery: time.Second,
		RetryLimit: 3, RetryBackoff: 10 * time.Millisecond,
	})

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("Flush should succeed after retries: %v", err)
	}
	if repo.saveCallCount.Load() != 3 {
		t.Errorf("expected 3 save calls (2 fail + 1 success), got %d", repo.saveCallCount.Load())
	}
}

func TestPersister_FlushDropsAfterRetryExhausted(t *testing.T) {
	t.Parallel()
	src := &fakeSource{
		snapshots: []asset.AssetSnapshot{{ID: "mac:aa:bb:cc:dd:ee:01", Status: asset.StatusOnline}},
	}
	repo := &fakeRepo{saveErr: errors.New("persistent")}
	repo.failNextN.Store(100)

	p := persist.New(repo, src, "run_4", slog.Default()).SetOptions(persist.Options{
		BatchSize: 10, FlushEvery: time.Second,
		RetryLimit: 3, RetryBackoff: 5 * time.Millisecond,
	})

	err := p.Flush(context.Background())
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if repo.saveCallCount.Load() != 3 {
		t.Errorf("expected 3 save calls (retry limit), got %d", repo.saveCallCount.Load())
	}

	flushCount, flushErrors, _ := p.Counters()
	if flushErrors != 1 {
		t.Errorf("expected 1 flush error, got %d", flushErrors)
	}
	if flushCount != 0 {
		t.Errorf("expected 0 successful flushes, got %d", flushCount)
	}
}

func TestPersister_CountersAfterSuccess(t *testing.T) {
	t.Parallel()
	src := &fakeSource{
		snapshots: []asset.AssetSnapshot{{ID: "mac:aa:bb:cc:dd:ee:01", Status: asset.StatusOnline}},
	}
	repo := &fakeRepo{}
	p := persist.New(repo, src, "run_5", slog.Default())

	p.Flush(context.Background())

	flushCount, flushErrors, lastFlush := p.Counters()
	if flushCount != 1 {
		t.Errorf("expected flushCount=1, got %d", flushCount)
	}
	if flushErrors != 0 {
		t.Errorf("expected flushErrors=0, got %d", flushErrors)
	}
	if lastFlush <= 0 {
		t.Errorf("expected lastFlush > 0, got %v", lastFlush)
	}
}

func TestPersister_OverflowSplitAcrossFlushes(t *testing.T) {
	t.Parallel()
	snaps := make([]asset.AssetSnapshot, 5)
	for i := range snaps {
		snaps[i] = asset.AssetSnapshot{
			ID:     asset.AssetID("id-" + string(rune('A'+i))),
			Status: asset.StatusOnline,
		}
	}
	src := &fakeSource{snapshots: snaps}
	repo := &fakeRepo{}
	p := persist.New(repo, src, "run_6", slog.Default()).SetOptions(persist.Options{
		BatchSize:    2,
		FlushEvery:   time.Second,
		RetryLimit:   1,
		RetryBackoff: 5 * time.Millisecond,
	})

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if repo.saveCallCount.Load() != 1 {
		t.Errorf("expected 1 save call, got %d", repo.saveCallCount.Load())
	}
	if len(repo.savedBatches[0].Assets) != 2 {
		t.Errorf("expected 2 assets in first batch, got %d", len(repo.savedBatches[0].Assets))
	}

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if repo.saveCallCount.Load() != 2 {
		t.Errorf("expected 2 save calls, got %d", repo.saveCallCount.Load())
	}
	if len(repo.savedBatches[1].Assets) != 2 {
		t.Errorf("expected 2 assets in second batch, got %d", len(repo.savedBatches[1].Assets))
	}

	if err := p.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if repo.saveCallCount.Load() != 3 {
		t.Errorf("expected 3 save calls, got %d", repo.saveCallCount.Load())
	}
	if len(repo.savedBatches[2].Assets) != 1 {
		t.Errorf("expected 1 asset in third batch, got %d", len(repo.savedBatches[2].Assets))
	}
}

func TestPersister_RunFinalFlushOnCancel(t *testing.T) {
	t.Parallel()
	src := &fakeSource{}
	repo := &fakeRepo{}
	p := persist.New(repo, src, "run_7", slog.Default()).SetOptions(persist.Options{
		BatchSize: 10, FlushEvery: 5 * time.Second,
		RetryLimit: 1, RetryBackoff: 5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if repo.saveCallCount.Load() != 0 {
		t.Errorf("expected 0 save calls for empty source, got %d", repo.saveCallCount.Load())
	}
}

func TestPersister_NoRetryOnContextCanceled(t *testing.T) {
	t.Parallel()
	src := &fakeSource{
		snapshots: []asset.AssetSnapshot{{ID: "mac:aa:bb:cc:dd:ee:01", Status: asset.StatusOnline}},
	}
	repo := &fakeRepo{saveErr: context.Canceled}
	repo.failNextN.Store(100)

	p := persist.New(repo, src, "run_8", slog.Default()).SetOptions(persist.Options{
		BatchSize: 10, FlushEvery: time.Second,
		RetryLimit: 5, RetryBackoff: 5 * time.Millisecond,
	})

	err := p.Flush(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if repo.saveCallCount.Load() != 1 {
		t.Errorf("expected 1 save call (no retry on canceled), got %d", repo.saveCallCount.Load())
	}
}

func TestPersister_SetOptions(t *testing.T) {
	t.Parallel()
	src := &fakeSource{}
	repo := &fakeRepo{}
	p := persist.New(repo, src, "run_9", slog.Default())

	p2 := p.SetOptions(persist.Options{
		BatchSize:  100,
		FlushEvery: 2 * time.Second,
	})
	if p2 == nil {
		t.Fatal("SetOptions should return non-nil")
	}
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("invalid MAC: %v", err)
	}
	return m
}

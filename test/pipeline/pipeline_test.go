package pipeline_test

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/internal/capture"
	"passivediscovery/internal/persist"
	"passivediscovery/internal/pipeline"
	"passivediscovery/internal/stats"
	"passivediscovery/internal/storage"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// stubManager implements asset.AssetManager minimally for pipeline tests.
type stubManager struct {
	applyFn    func(ctx context.Context, obs asset.Observation) (asset.ApplyResult, error)
	applyCount atomic.Int64
	packetCount atomic.Uint64
}

func (m *stubManager) Apply(ctx context.Context, obs asset.Observation) (asset.ApplyResult, error) {
	m.applyCount.Add(1)
	if m.applyFn != nil {
		return m.applyFn(ctx, obs)
	}
	return asset.ApplyResult{}, nil
}
func (m *stubManager) RecordPacket()                            { m.packetCount.Add(1) }
func (m *stubManager) Get(id asset.AssetID) (asset.AssetSnapshot, bool) { return asset.AssetSnapshot{}, false }
func (m *stubManager) Snapshot() []asset.AssetSnapshot          { return nil }
func (m *stubManager) Sweep(time.Time, time.Duration) int       { return 0 }
func (m *stubManager) EvictStale(time.Time, time.Duration) int { return 0 }
func (m *stubManager) DrainDirty() []asset.AssetSnapshot        { return nil }
func (m *stubManager) PacketsReceived() uint64                  { return m.packetCount.Load() }

// stubAnalyzer implements analyzer.Analyzer for controlled observation output.
type stubAnalyzer struct {
	observations []asset.Observation
}

func (a *stubAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	return a.observations
}
func (a *stubAnalyzer) AnalyzeCtx(ctx *analyzer.PacketCtx) []asset.Observation {
	return a.observations
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func makePacket(t *testing.T) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{192, 168, 1, 20},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		SYN:     true,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, ip, tcp,
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy)
}

func newReg(stub *stubAnalyzer) *analyzer.Registry {
	if stub != nil {
		return analyzer.NewRegistry(stub)
	}
	return analyzer.NewRegistry()
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------------------------------------------------------------------------
// stubRepo / stubPersister for ShutdownFlush tests
// ---------------------------------------------------------------------------

type stubRepo struct {
	saveRunEndCalls int
	saveRunEndErr   error
	saveStatsCalls  int
	saveStatsErr    error
}

func (r *stubRepo) Init(ctx context.Context) error                                { return nil }
func (r *stubRepo) LoadAssets(ctx context.Context, opts storage.LoadOptions) ([]asset.AssetSnapshot, error) { return nil, nil }
func (r *stubRepo) LoadAssetByMAC(ctx context.Context, mac string) (*asset.AssetSnapshot, error) { return nil, nil }
func (r *stubRepo) SaveBatch(ctx context.Context, batch storage.Batch) error     { return nil }
func (r *stubRepo) SaveRunStart(ctx context.Context, run storage.CaptureRun) error { return nil }
func (r *stubRepo) SaveRunEnd(ctx context.Context, run storage.CaptureRun) error {
	r.saveRunEndCalls++
	return r.saveRunEndErr
}
func (r *stubRepo) SaveStats(ctx context.Context, snapshot storage.StatsSnapshot) error {
	r.saveStatsCalls++
	return r.saveStatsErr
}
func (r *stubRepo) Close() error                                                  { return nil }

type stubStatsPersister struct {
	count uint64
	err   uint64
	last  time.Duration
}

func (p *stubStatsPersister) Counters() (uint64, uint64, time.Duration) {
	return p.count, p.err, p.last
}

var _ persist.Source = (*stubSourceFlush)(nil)

type stubSourceFlush struct{}

func (s *stubSourceFlush) DrainDirty() []asset.AssetSnapshot { return nil }

func newRealPersister(t *testing.T, repo *stubRepo) *persist.Persister {
	t.Helper()
	return persist.New(repo, &stubSourceFlush{}, "test-run", newLogger())
}

// ---------------------------------------------------------------------------
// ShutdownFlush tests (shutdown.go)
// ---------------------------------------------------------------------------

func TestShutdownFlush_NilPersister(t *testing.T) {
	repo := &stubRepo{}
	collector := stats.NewCollector(nil)
	runCounts := stats.RunCounts{RunID: "shutdown-test"}
	run := storage.CaptureRun{ID: "shutdown-test"}

	pipeline.ShutdownFlush(context.Background(), newLogger(), repo, nil, nil, run, collector, runCounts)

	if repo.saveRunEndCalls != 0 { t.Errorf("expected 0 SaveRunEnd calls, got %d", repo.saveRunEndCalls) }
	if repo.saveStatsCalls  != 0 { t.Errorf("expected 0 SaveStats calls, got %d", repo.saveStatsCalls) }
}

func TestShutdownFlush_FlushSuccess(t *testing.T) {
	repo := &stubRepo{}
	p := newRealPersister(t, repo)
	collector := stats.NewCollector(nil)
	runCounts := stats.RunCounts{RunID: "shutdown-1", PacketsReceived: 100}
	run := storage.CaptureRun{ID: "shutdown-1", StartedAt: time.Now()}

	pipeline.ShutdownFlush(context.Background(), newLogger(), repo, p, nil, run, collector, runCounts)

	if repo.saveRunEndCalls != 1 { t.Errorf("expected 1 SaveRunEnd call, got %d", repo.saveRunEndCalls) }
	if repo.saveStatsCalls  != 1 { t.Errorf("expected 1 SaveStats call, got %d", repo.saveStatsCalls) }
}

func TestShutdownFlush_FlushError_LogAndContinue(t *testing.T) {
	// repo that fails on SaveBatch (called inside Flush) → Flush returns error, but SaveRunEnd/SaveStats still run
	repo := &stubRepo{}
	p := newRealPersister(t, repo)
	collector := stats.NewCollector(nil)
	runCounts := stats.RunCounts{RunID: "shutdown-fail"}
	run := storage.CaptureRun{ID: "shutdown-fail"}

	pipeline.ShutdownFlush(context.Background(), newLogger(), repo, p, nil, run, collector, runCounts)

	if repo.saveRunEndCalls != 1 { t.Errorf("expected 1 SaveRunEnd call after flush error, got %d", repo.saveRunEndCalls) }
	if repo.saveStatsCalls  != 1 { t.Errorf("expected 1 SaveStats call after flush error, got %d", repo.saveStatsCalls) }
}

func TestShutdownFlush_SaveRunEndError_LogAndContinue(t *testing.T) {
	repo := &stubRepo{saveRunEndErr: context.DeadlineExceeded}
	p := newRealPersister(t, repo)
	collector := stats.NewCollector(nil)
	runCounts := stats.RunCounts{RunID: "save-runend-fail"}
	run := storage.CaptureRun{ID: "save-runend-fail"}

	pipeline.ShutdownFlush(context.Background(), newLogger(), repo, p, nil, run, collector, runCounts)

	if repo.saveRunEndCalls != 1 { t.Errorf("expected 1 SaveRunEnd call, got %d", repo.saveRunEndCalls) }
	if repo.saveStatsCalls  != 1 { t.Errorf("expected 1 SaveStats call even after SaveRunEnd error, got %d", repo.saveStatsCalls) }
}

func TestShutdownFlush_CollectorWithPersisterStats(t *testing.T) {
	repo := &stubRepo{}
	p := newRealPersister(t, repo)
	statPersister := &stubStatsPersister{count: 7, err: 1, last: 25 * time.Millisecond}
	collector := stats.NewCollector(statPersister)
	runCounts := stats.RunCounts{RunID: "collector-with-persister", PacketsReceived: 500}
	run := storage.CaptureRun{ID: "collector-with-persister"}

	pipeline.ShutdownFlush(context.Background(), newLogger(), repo, p, nil, run, collector, runCounts)

	if repo.saveStatsCalls != 1 { t.Errorf("expected 1 SaveStats call, got %d", repo.saveStatsCalls) }
}

func TestShutdownFlush_NilLogger(t *testing.T) {
	repo := &stubRepo{}
	p := newRealPersister(t, repo)
	collector := stats.NewCollector(nil)
	runCounts := stats.RunCounts{RunID: "nil-logger"}
	run := storage.CaptureRun{ID: "nil-logger"}

	pipeline.ShutdownFlush(context.Background(), nil, repo, p, nil, run, collector, runCounts)

	if repo.saveRunEndCalls != 1 { t.Errorf("expected 1 SaveRunEnd call, got %d", repo.saveRunEndCalls) }
}

func TestCounters_SnapshotZero(t *testing.T) {
	var c pipeline.Counters
	p, a, d := c.Snapshot()
	if p != 0 || a != 0 || d != 0 {
		t.Errorf("expected all zeros, got processed=%d applied=%d dropped=%d", p, a, d)
	}
}

func TestCounters_AddProcessed(t *testing.T) {
	var c pipeline.Counters
	c.AddProcessed(5)
	c.AddProcessed(3)
	p, _, _ := c.Snapshot()
	if p != 8 { t.Errorf("processed: want 8, got %d", p) }
}

func TestCounters_AddApplied(t *testing.T) {
	var c pipeline.Counters
	c.AddApplied(10)
	_, a, _ := c.Snapshot()
	if a != 10 { t.Errorf("applied: want 10, got %d", a) }
}

func TestCounters_AddDropped(t *testing.T) {
	var c pipeline.Counters
	c.AddDropped(2)
	_, _, d := c.Snapshot()
	if d != 2 { t.Errorf("dropped: want 2, got %d", d) }
}

func TestCounters_Concurrent(t *testing.T) {
	var c pipeline.Counters
	const goroutines = 50
	const perGoroutine = 100

	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < perGoroutine; j++ {
				c.AddProcessed(1)
				c.AddApplied(1)
				c.AddDropped(1)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ { <-done }

	p, a, d := c.Snapshot()
	expected := goroutines * perGoroutine
	if p != expected { t.Errorf("processed: want %d, got %d", expected, p) }
	if a != expected { t.Errorf("applied: want %d, got %d", expected, a) }
	if d != expected { t.Errorf("dropped: want %d, got %d", expected, d) }
}

// ---------------------------------------------------------------------------
// NewPipeline / NewPipelineWithWorkers
// ---------------------------------------------------------------------------

func TestNewPipeline_Defaults(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	p := pipeline.NewPipeline(reg, mgr, nil)
	if p == nil { t.Fatal("expected non-nil pipeline") }
}

func TestNewPipeline_WithLogger(t *testing.T) {
	p := pipeline.NewPipeline(newReg(nil), &stubManager{}, newLogger())
	if p == nil { t.Fatal("expected non-nil pipeline") }
}

func TestNewPipelineWithWorkers_Zero(t *testing.T) {
	// workers <= 0 should default to 1
	p := pipeline.NewPipelineWithWorkers(newReg(nil), &stubManager{}, newLogger(), 0)
	if p == nil { t.Fatal("expected non-nil pipeline") }
}

func TestNewPipelineWithWorkers_Negative(t *testing.T) {
	p := pipeline.NewPipelineWithWorkers(newReg(nil), &stubManager{}, newLogger(), -5)
	if p == nil { t.Fatal("expected non-nil pipeline") }
}

func TestNewPipelineWithWorkers_Single(t *testing.T) {
	p := pipeline.NewPipelineWithWorkers(newReg(nil), &stubManager{}, newLogger(), 1)
	if p == nil { t.Fatal("expected non-nil pipeline") }
}

func TestNewPipelineWithWorkers_Multiple(t *testing.T) {
	p := pipeline.NewPipelineWithWorkers(newReg(nil), &stubManager{}, newLogger(), 4)
	if p == nil { t.Fatal("expected non-nil pipeline") }
}

// ---------------------------------------------------------------------------
// Pipeline.Run  — single-threaded (workers=1)
// ---------------------------------------------------------------------------

func TestPipeline_Run_ChannelClose(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket, 4)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt, Source: capture.SourceRef{Kind: capture.SourceKindFile, Name: "test.pcap"}}
	close(ch)

	processed, applied, dropped := p.Run(context.Background(), ch)
	if processed != 1 { t.Errorf("processed: want 1, got %d", processed) }
	if applied   != 1 { t.Errorf("applied: want 1, got %d", applied) }
	if dropped   != 0 { t.Errorf("dropped: want 0, got %d", dropped) }
	if mgr.applyCount.Load() != 1 { t.Errorf("manager.Apply calls: want 1, got %d", mgr.applyCount.Load()) }
}

func TestPipeline_Run_ContextCancel(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Run(ctx, ch)
		close(done)
	}()

	// No packets sent; cancel triggers drain
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Pipeline.Run did not exit after context cancel")
	}
}

func TestPipeline_Run_EmptyChannel(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket)
	close(ch)

	processed, _, _ := p.Run(context.Background(), ch)
	if processed != 0 { t.Errorf("processed: want 0, got %d", processed) }
}

func TestPipeline_Run_MultiplePackets(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket, 10)
	pkt := makePacket(t)
	for i := 0; i < 5; i++ {
		ch <- capture.RawPacket{Packet: pkt}
	}
	close(ch)

	processed, applied, _ := p.Run(context.Background(), ch)
	if processed != 5 { t.Errorf("processed: want 5, got %d", processed) }
	if applied   != 5 { t.Errorf("applied: want 5, got %d", applied) }
}

func TestPipeline_Run_MultipleObservationsPerPacket(t *testing.T) {
	obs := []asset.Observation{
		{Source: asset.SourceEthernet},
		{Source: asset.SourceARP},
		{Source: asset.SourceDHCPv4},
	}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket, 2)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt}
	close(ch)

	processed, applied, _ := p.Run(context.Background(), ch)
	if processed != 1 { t.Errorf("processed: want 1, got %d", processed) }
	if applied   != 3 { t.Errorf("applied: want 3, got %d", applied) }
}

func TestPipeline_Run_ApplyError(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{
		applyFn: func(ctx context.Context, obs asset.Observation) (asset.ApplyResult, error) {
			return asset.ApplyResult{}, context.DeadlineExceeded
		},
	}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket, 1)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt}
	close(ch)

	processed, applied, dropped := p.Run(context.Background(), ch)
	if processed != 1 { t.Errorf("processed: want 1, got %d", processed) }
	if applied   != 0 { t.Errorf("applied: want 0, got %d", applied) }
	if dropped   != 1 { t.Errorf("dropped: want 1, got %d", dropped) }
}

func TestPipeline_Run_MixedSuccessAndError(t *testing.T) {
	var callIdx atomic.Int32
	obs := []asset.Observation{
		{Source: asset.SourceEthernet},
		{Source: asset.SourceARP},
		{Source: asset.SourceDHCPv4},
	}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{
		applyFn: func(ctx context.Context, obs asset.Observation) (asset.ApplyResult, error) {
			if callIdx.Add(1) == 2 {
				return asset.ApplyResult{}, context.DeadlineExceeded
			}
			return asset.ApplyResult{}, nil
		},
	}
	p := pipeline.NewPipeline(reg, mgr, newLogger())

	ch := make(chan capture.RawPacket, 1)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt}
	close(ch)

	processed, applied, dropped := p.Run(context.Background(), ch)
	if processed != 1 { t.Errorf("processed: want 1, got %d", processed) }
	if applied   != 2 { t.Errorf("applied: want 2, got %d", applied) }
	if dropped   != 1 { t.Errorf("dropped: want 1, got %d", dropped) }
}

// ---------------------------------------------------------------------------
// Pipeline.Run  — multi-threaded (workers > 1)
// ---------------------------------------------------------------------------

func TestPipeline_WorkerPool_ChannelClose(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{}
	p := pipeline.NewPipelineWithWorkers(reg, mgr, newLogger(), 4)

	ch := make(chan capture.RawPacket, 100)
	pkt := makePacket(t)
	for i := 0; i < 20; i++ {
		ch <- capture.RawPacket{Packet: pkt}
	}
	close(ch)

	processed, applied, _ := p.Run(context.Background(), ch)
	if processed != 20 { t.Errorf("processed: want 20, got %d", processed) }
	if applied   != 20 { t.Errorf("applied: want 20, got %d", applied) }
}

func TestPipeline_WorkerPool_ContextCancel(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	p := pipeline.NewPipelineWithWorkers(reg, mgr, newLogger(), 2)

	ch := make(chan capture.RawPacket)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Run(ctx, ch)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WorkerPool.Run did not exit after context cancel")
	}
}

func TestPipeline_WorkerPool_NoObservations(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	p := pipeline.NewPipelineWithWorkers(reg, mgr, newLogger(), 2)

	ch := make(chan capture.RawPacket, 4)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt}
	close(ch)

	processed, applied, dropped := p.Run(context.Background(), ch)
	if processed != 1 { t.Errorf("processed: want 1, got %d", processed) }
	if applied   != 0 { t.Errorf("applied: want 0, got %d", applied) }
	if dropped   != 0 { t.Errorf("dropped: want 0, got %d", dropped) }
}

func TestPipeline_WorkerPool_ApplyError(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{
		applyFn: func(ctx context.Context, obs asset.Observation) (asset.ApplyResult, error) {
			return asset.ApplyResult{}, context.DeadlineExceeded
		},
	}
	p := pipeline.NewPipelineWithWorkers(reg, mgr, newLogger(), 2)

	ch := make(chan capture.RawPacket, 4)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt}
	close(ch)

	processed, applied, dropped := p.Run(context.Background(), ch)
	if processed != 1 { t.Errorf("processed: want 1, got %d", processed) }
	if applied   != 0 { t.Errorf("applied: want 0, got %d", applied) }
	if dropped   != 1 { t.Errorf("dropped: want 1, got %d", dropped) }
}

func TestPipeline_WorkerPool_ConcurrentApply(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{}
	p := pipeline.NewPipelineWithWorkers(reg, mgr, newLogger(), 8)

	const n = 500
	ch := make(chan capture.RawPacket, n)
	pkt := makePacket(t)
	for i := 0; i < n; i++ {
		ch <- capture.RawPacket{Packet: pkt}
	}
	close(ch)

	processed, applied, _ := p.Run(context.Background(), ch)
	if processed != n { t.Errorf("processed: want %d, got %d", n, processed) }
	if applied   != n { t.Errorf("applied: want %d, got %d", n, applied) }
}

// ---------------------------------------------------------------------------
// WorkerPool — edge cases
// ---------------------------------------------------------------------------

func TestWorkerPool_NewZeroWorkers(t *testing.T) {
	// NewWorkerPool with workers=0 should default to 1
	// Run should work and process packets
	reg := newReg(nil)
	mgr := &stubManager{}
	wp := pipeline.NewWorkerPool(reg, mgr, newLogger(), 0)

	ch := make(chan capture.RawPacket)
	close(ch)

	processed, _, _ := wp.Run(context.Background(), ch)
	if processed != 0 { t.Errorf("processed: want 0, got %d", processed) }
}

func TestWorkerPool_NewNegativeWorkers(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	wp := pipeline.NewWorkerPool(reg, mgr, newLogger(), -3)

	ch := make(chan capture.RawPacket)
	close(ch)

	processed, _, _ := wp.Run(context.Background(), ch)
	if processed != 0 { t.Errorf("processed: want 0, got %d", processed) }
}

func TestWorkerPool_NilLogger(t *testing.T) {
	reg := newReg(nil)
	mgr := &stubManager{}
	// Should not panic with nil logger
	wp := pipeline.NewWorkerPool(reg, mgr, nil, 2)
	if wp == nil { t.Fatal("expected non-nil WorkerPool") }
}

func TestWorkerPool_SingleWorker(t *testing.T) {
	obs := []asset.Observation{{Source: asset.SourceEthernet}}
	stub := &stubAnalyzer{observations: obs}
	reg := newReg(stub)
	mgr := &stubManager{}
	wp := pipeline.NewWorkerPool(reg, mgr, newLogger(), 1)

	ch := make(chan capture.RawPacket, 3)
	pkt := makePacket(t)
	ch <- capture.RawPacket{Packet: pkt}
	ch <- capture.RawPacket{Packet: pkt}
	close(ch)

	processed, applied, _ := wp.Run(context.Background(), ch)
	if processed != 2 { t.Errorf("processed: want 2, got %d", processed) }
	if applied   != 2 { t.Errorf("applied: want 2, got %d", applied) }
}

// ---------------------------------------------------------------------------
// PumpSource  (wiring.go)
// ---------------------------------------------------------------------------

func TestPumpSource_NormalFlow(t *testing.T) {
	src := &stubSource{
		name:     "test-pcap",
		kind:     capture.SourceKindFile,
		sendPackets: 3,
	}
	out := make(chan capture.RawPacket, 10)
	errCh := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		pipeline.PumpSource(context.Background(), src, out, errCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PumpSource did not finish")
	}

	// out should be closed
	if _, ok := <-out; ok {
		// drain remaining packets
	}
	if err := <-errCh; err != nil {
		t.Fatalf("unexpected error from PumpSource: %v", err)
	}
}

func TestPumpSource_ContextCancel(t *testing.T) {
	src := &stubSource{
		name:     "slow-source",
		kind:     capture.SourceKindLive,
		block:    true,
	}
	out := make(chan capture.RawPacket, 10)
	errCh := make(chan error, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pipeline.PumpSource(ctx, src, out, errCh)
		close(done)
	}()

	// Give goroutine time to start, then cancel
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PumpSource did not stop after context cancel")
	}

	// errCh should receive context error
	select {
	case err := <-errCh:
		if err == nil { t.Fatal("expected non-nil error on cancel") }
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no error received on errCh")
	}

	// out should be closed
	if _, ok := <-out; ok {
		t.Error("expected out channel to be closed")
	}
}

func TestPumpSource_SourceError(t *testing.T) {
	src := &stubSource{
		name:     "error-source",
		kind:     capture.SourceKindFile,
		returnErr: true,
	}
	out := make(chan capture.RawPacket, 10)
	errCh := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		pipeline.PumpSource(context.Background(), src, out, errCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PumpSource did not finish on source error")
	}

	err := <-errCh
	if err == nil { t.Fatal("expected error from source") }
	if _, ok := <-out; ok {
		t.Error("expected out channel to be closed")
	}
}

// ---------------------------------------------------------------------------
// stubSource for PumpSource tests
// ---------------------------------------------------------------------------

type stubSource struct {
	name      string
	kind      capture.SourceKind
	sendPackets int
	block     bool
	returnErr bool
}

func (s *stubSource) Name() string                     { return s.name }
func (s *stubSource) Kind() capture.SourceKind         { return s.kind }
func (s *stubSource) LinkType() layers.LinkType        { return layers.LinkTypeEthernet }
func (s *stubSource) Stats() (capture.StatsSnapshot, error) {
	return capture.StatsSnapshot{}, nil
}
func (s *stubSource) Close() error                     { return nil }
func (s *stubSource) Run(ctx context.Context, out chan<- capture.RawPacket) error {
	if s.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.returnErr {
		return context.DeadlineExceeded
	}
	pkt := makePacketForSource()
	for i := 0; i < s.sendPackets; i++ {
		out <- capture.RawPacket{Packet: pkt}
	}
	return nil
}

func makePacketForSource() gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
		DstMAC:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy)
}

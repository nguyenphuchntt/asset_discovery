package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/internal/capture"
)

type WorkerPool struct {
	registry *analyzer.Registry
	manager  asset.AssetManager
	logger   *slog.Logger
	counters *Counters
	workers  int
}

func NewWorkerPool(reg *analyzer.Registry, mgr asset.AssetManager, logger *slog.Logger, workers int) *WorkerPool {
	if logger == nil {
		logger = slog.Default()
	}
	if workers <= 0 {
		workers = 1
	}
	return &WorkerPool{
		registry: reg,
		manager:  mgr,
		logger:   logger.With(slog.String("component", "pipeline.workerpool")),
		counters: new(Counters),
		workers:  workers,
	}
}

func (wp *WorkerPool) Run(ctx context.Context, rawPackets <-chan capture.RawPacket) (processed, applied, dropped int) {
	var wg sync.WaitGroup
	for i := 0; i < wp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wp.workerLoop(ctx, rawPackets)
		}()
	}
	wg.Wait()
	return wp.counters.Snapshot()
}

func (wp *WorkerPool) workerLoop(ctx context.Context, rawPackets <-chan capture.RawPacket) {
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-rawPackets:
			if !ok {
				return
			}
			wp.counters.AddProcessed(1)
			wp.manager.RecordPacket()
			observations := wp.registry.Analyze(raw.Packet)
			for _, obs := range observations {
				if _, err := wp.manager.Apply(ctx, obs); err != nil {
					wp.counters.AddDropped(1)
					wp.logger.Warn("manager.Apply failed",
						slog.String("source", string(obs.Source)),
						slog.String("err", err.Error()),
					)
					continue
				}
				wp.counters.AddApplied(1)
			}
		}
	}
}
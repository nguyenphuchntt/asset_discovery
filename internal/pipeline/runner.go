package pipeline

import (
	"context"
	"log/slog"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/internal/capture"
)

type Pipeline struct {
	registry *analyzer.Registry
	manager  asset.AssetManager
	logger   *slog.Logger
	counters *Counters
	workers  int
}

func NewPipeline(reg *analyzer.Registry, mgr asset.AssetManager, logger *slog.Logger) *Pipeline {
	return NewPipelineWithWorkers(reg, mgr, logger, 1)
}

// NewPipelineWithWorkers tạo pipeline với số workers chỉ định.
// workers=1 chạy single-threaded loop; workers>1 delegate sang WorkerPool.
func NewPipelineWithWorkers(reg *analyzer.Registry, mgr asset.AssetManager, logger *slog.Logger, workers int) *Pipeline {
	if logger == nil {
		logger = slog.Default()
	}
	if workers <= 0 {
		workers = 1
	}
	return &Pipeline{
		registry: reg,
		manager:  mgr,
		logger:   logger.With(slog.String("component", "pipeline")),
		counters: new(Counters),
		workers:  workers,
	}
}

// Run drains rawPackets until channel closes (PCAP EOF) or ctx cancels (live shutdown).
func (p *Pipeline) Run(ctx context.Context, rawPackets <-chan capture.RawPacket) (processed, applied, dropped int) {
	if p.workers > 1 {
		pool := NewWorkerPool(p.registry, p.manager, p.logger, p.workers)
		return pool.Run(ctx, rawPackets)
	}

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("pipeline cancelled, draining")
			return p.counters.Snapshot()
		case raw, ok := <-rawPackets:
			if !ok {
				return p.counters.Snapshot()
			}

			p.counters.AddProcessed(1)

			observations := p.registry.Analyze(raw.Packet)
			for _, obs := range observations {
				if _, err := p.manager.Apply(ctx, obs); err != nil {
					p.counters.AddDropped(1)
					p.logger.Warn("manager.Apply failed",
						slog.String("source", string(obs.Source)),
						slog.String("err", err.Error()),
					)
					continue
				}
				p.counters.AddApplied(1)
			}
		}
	}
}
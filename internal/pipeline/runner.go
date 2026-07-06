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
}

func NewPipeline(reg *analyzer.Registry, mgr asset.AssetManager, logger *slog.Logger) *Pipeline {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pipeline{
		registry: reg,
		manager:  mgr,
		logger:   logger.With(slog.String("component", "pipeline")),
		counters: new(Counters),
	}
}

func (p *Pipeline) Run(ctx context.Context, rawPackets <-chan capture.RawPacket) (processed, applied, dropped int) {
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
				if _, err := p.manager.Apply(obs); err != nil {
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
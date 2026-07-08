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
				res, err := wp.manager.Apply(ctx, obs)
				if err != nil {
					wp.counters.AddDropped(1)
					wp.manager.RecordDrop()
					wp.logger.Warn("event",
						slog.String("event", "apply_failed"),
						slog.String("source", string(obs.Source)),
						slog.String("mac", obs.MAC.String()),
						slog.String("err", err.Error()),
					)
					continue
				}
				wp.counters.AddApplied(1)
				logObservationEvent(wp.logger, res, obs)
			}
		}
	}
}

// logObservationEvent emits a structured asset_created or asset_updated log
// when the manager records a meaningful change.
func logObservationEvent(logger *slog.Logger, res asset.ApplyResult, obs asset.Observation) {
	if res.Action != asset.ActionCreated && res.Action != asset.ActionUpdated {
		return
	}
	args := []any{
		slog.String("event", string(res.Action)),
		slog.String("mac", obs.MAC.String()),
		slog.String("source", string(obs.Source)),
	}
	if obs.MACVendor != "" {
		args = append(args, slog.String("vendor", obs.MACVendor))
	}
	if ip := firstIPv4(obs.IPv4s); ip != "" {
		args = append(args, slog.String("ip", ip))
	}
	if len(obs.Hostnames) > 0 {
		args = append(args, slog.String("hostname", obs.Hostnames[0]))
	}
	logger.Info("event", args...)
}

func firstIPv4(m map[string]asset.IPEntry) string {
	for ip := range m {
		return ip
	}
	return ""
}
package pipeline

import (
	"context"
	"log/slog"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/persist"
	"passivediscovery/internal/stats"
	"passivediscovery/internal/storage"
)

func ShutdownFlush(
	ctx context.Context,
	logger *slog.Logger,
	repo storage.Repository,
	persister *persist.Persister,
	manager *asset.Manager,
	run storage.CaptureRun,
	collector *stats.Collector,
	runCounts stats.RunCounts,
) {
	if persister == nil {
		return
	}
	shutdownCtx, flushCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer flushCancel()
	if err := persister.Flush(shutdownCtx); err != nil {
		logger.Error("final persist flush failed", slog.String("err", err.Error()))
	}
	if err := repo.SaveRunEnd(context.Background(), run); err != nil {
		logger.Error("save run end failed", slog.String("err", err.Error()))
	}
	snap := collector.Snapshot(context.Background(), runCounts)
	_ = repo.SaveStats(context.Background(), snap)
}
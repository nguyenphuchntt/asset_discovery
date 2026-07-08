package pipeline

import (
	"context"
	"log/slog"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/persist"
	"passivediscovery/internal/storage"
)

func ShutdownFlush(
	ctx context.Context,
	logger *slog.Logger,
	repo storage.Repository,
	persister *persist.Persister,
	manager *asset.Manager,
) {
	if persister == nil {
		return
	}
	shutdownCtx, flushCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer flushCancel()
	if err := persister.Flush(shutdownCtx); err != nil {
		logger.Error("event",
			slog.String("event", "flush_failed"),
			slog.String("err", err.Error()),
		)
	}
}

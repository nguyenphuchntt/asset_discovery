package pipeline

import (
	"context"
	"log/slog"

	"passivediscovery/internal/capture"
)

func PumpSource(ctx context.Context, source capture.Source, out chan<- capture.RawPacket, errCh chan<- error) {
	defer close(out)
	logger := slog.Default().With(slog.String("component", "pipeline.source"))

	logger.Info("source started",
		slog.String("name", source.Name()),
		slog.String("kind", string(source.Kind())),
	)
	errCh <- source.Run(ctx, out)
}
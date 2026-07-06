package lifecycle

import (
	"context"
	"log/slog"
	"time"

	"passivediscovery/internal/asset"
)

type Manager interface {
	Sweep(now time.Time, offlineAfter time.Duration) []asset.Event
	EvictStale(now time.Time, evictAfter time.Duration) int
}

type Tracker struct {
	manager      Manager
	clock        Clock
	interval     time.Duration
	offlineAfter time.Duration
	evictAfter   time.Duration
	logger       *slog.Logger
}

func NewTracker(mgr Manager, clock Clock, interval, offlineAfter, evictAfter time.Duration, logger *slog.Logger) *Tracker {
	if clock == nil {
		clock = RealClock{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Tracker{
		manager:      mgr,
		clock:        clock,
		interval:     interval,
		offlineAfter: offlineAfter,
		evictAfter:   evictAfter,
		logger:       logger.With(slog.String("component", "lifecycle")),
	}
}

func (t *Tracker) Run(ctx context.Context) error {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	t.logger.Info("lifecycle tracker started",
		slog.Duration("interval", t.interval),
		slog.Duration("offline_after", t.offlineAfter),
		slog.Duration("evict_after", t.evictAfter),
	)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("lifecycle tracker stopped")
			return nil
		case now := <-ticker.C:
			events := t.manager.Sweep(now, t.offlineAfter)
			if n := len(events); n > 0 {
				t.logger.Info("lifecycle sweep transitioned assets",
					slog.Int("count", n),
					slog.Time("now", now),
				)
			}
			if evicted := t.manager.EvictStale(now, t.evictAfter); evicted > 0 {
				t.logger.Info("evicted stale assets",
					slog.Int("count", evicted),
					slog.Time("now", now),
				)
			}
		}
	}
}
package stats

import (
	"context"
	"time"

	"passivediscovery/internal/storage"
)

type PersisterStats interface {
	Counters() (flushCount, flushErrors uint64, lastFlush time.Duration)
}

// Collector aggregates counters from multiple subsystems into a single
// storage.StatsSnapshot suitable for persisting to the runtime_stats table.
type Collector struct {
	persister PersisterStats
}

func NewCollector(persister PersisterStats) *Collector {
	return &Collector{persister: persister}
}

type RunCounts struct {
	RunID            string
	PacketsReceived  uint64
	Observations     uint64
	AssetsCreated    uint64
	AssetsUpdated    uint64
	KernelDropped    uint64
	InternalDropped  uint64
	RawQueueDepth    int
	PersistQueueDepth int
}

func (c *Collector) Snapshot(_ context.Context, run RunCounts) storage.StatsSnapshot {
	var flushCount, flushErrors uint64
	var flushLast time.Duration
	if c.persister != nil {
		flushCount, flushErrors, flushLast = c.persister.Counters()
	}
	return storage.StatsSnapshot{
		RunID:              run.RunID,
		CapturedAt:         time.Now().UTC(),
		PacketsReceived:    run.PacketsReceived,
		Observations:       run.Observations,
		AssetsCreated:      run.AssetsCreated,
		AssetsUpdated:      run.AssetsUpdated,
		KernelDropped:      run.KernelDropped,
		InternalDropped:    run.InternalDropped,
		RawQueueDepth:      run.RawQueueDepth,
		PersistQueueDepth:  run.PersistQueueDepth,
		DBFlushCount:       flushCount,
		DBFlushErrors:      flushErrors,
		DBFlushLast:        flushLast,
	}
}
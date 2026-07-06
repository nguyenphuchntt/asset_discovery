package api

import (
	"time"

	"passivediscovery/internal/asset"
)

// StatsSnapshot holds the runtime counters for the dashboard.
type StatsSnapshot struct {
	PacketsReceived uint64
	Observations    uint64
	AssetsCreated   uint64
	AssetsUpdated   uint64
	KernelDropped   uint64
	InternalDropped uint64
	RawQueueDepth   int
	DBFlushErrors   uint64
	AssetsTotal     int
	AssetsOnline    int
	AssetsOffline   int
}

// PersisterStats provides the DB flush counters from the Persister.
type PersisterStats interface {
	Counters() (flushCount, flushErrors uint64, lastFlush time.Duration)
}

// InMemoryStats reads live counters from the Manager snapshot and Persister
// to provide runtime data for the /api/stats endpoint.
type InMemoryStats struct {
	Manager   *asset.Manager
	Persister PersisterStats
}

// GetStats returns the current runtime counters.
func (s *InMemoryStats) GetStats() StatsSnapshot {
	snap := StatsSnapshot{}

	if s.Manager != nil {
		for _, a := range s.Manager.Snapshot() {
			snap.AssetsTotal++
			switch a.Status {
			case asset.StatusOnline:
				snap.AssetsOnline++
			case asset.StatusOffline:
				snap.AssetsOffline++
			}
		}
	}

	if s.Persister != nil {
		flushCount, flushErrors, _ := s.Persister.Counters()
		snap.DBFlushErrors = flushErrors
		_ = flushCount
	}

	return snap
}

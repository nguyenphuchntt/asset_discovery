package storage

import "time"

type SQLiteOptions struct {
	Path        string
	WAL         bool
	BusyTimeout time.Duration
}

type CaptureRun struct {
	ID            string
	Mode          string
	SourceName    string
	PCAPPath      string
	InterfaceName string
	StartedAt     time.Time
	EndedAt       time.Time

	PacketsReceived uint64
	Observations    uint64
	AssetsCreated   uint64
	AssetsUpdated   uint64
	KernelDropped   uint64
	InternalDropped uint64
	Errors          uint64
}

type StatsSnapshot struct {
	RunID             string
	CapturedAt        time.Time
	PacketsReceived  uint64
	Observations     uint64
	AssetsCreated    uint64
	AssetsUpdated    uint64
	KernelDropped    uint64
	InternalDropped  uint64
	RawQueueDepth    int
	PersistQueueDepth int
	DBFlushCount      uint64
	DBFlushErrors     uint64
	DBFlushLast       time.Duration
}

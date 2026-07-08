package storage

import "time"

type SQLiteOptions struct {
	Path        string
	WAL         bool
	BusyTimeout time.Duration
}

type Statistics struct {
	CapturedAt      time.Time
	PacketsReceived uint64
	AssetsCount     uint64
	PacketsPerSec   float64
}

type LoadOptions struct {
	Since time.Time // only assets with last_seen >= Since; zero = no time filter
	Limit int       // hard cap on rows returned; 0 = unlimited
}

package capture

import "sync/atomic"

type Stats struct {
	SourceName string
	SourceKind SourceKind

	received atomic.Uint64
	bytes    atomic.Uint64

	dropped atomic.Uint64
}

func NewStats(name string, kind SourceKind) *Stats {
	return &Stats{SourceName: name, SourceKind: kind}
}

func (s *Stats) RecordAccepted(length, captureLength int) {
	if s == nil {
		return
	}
	s.received.Add(1)
	switch {
	case length > 0:
		s.bytes.Add(uint64(length))
	case captureLength > 0:
		s.bytes.Add(uint64(captureLength))
	}
}

func (s *Stats) SetDropped(n uint64) {
	if s == nil {
		return
	}
	s.dropped.Store(n)
}

type StatsSnapshot struct {
	SourceName string
	SourceKind SourceKind

	Received uint64
	Bytes    uint64
	Dropped  uint64
	Filtered uint64
}

func (s *Stats) Snapshot() StatsSnapshot {
	if s == nil {
		return StatsSnapshot{}
	}
	return StatsSnapshot{
		SourceName: s.SourceName,
		SourceKind: s.SourceKind,
		Received:   s.received.Load(),
		Bytes:      s.bytes.Load(),
		Dropped:    s.dropped.Load(),
	}
}
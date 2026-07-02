package capture

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SourceKind string

const (
	SourceKindFile SourceKind = "file"
	SourceKindLive SourceKind = "live"
)

type RawPacket struct {
	Packet        gopacket.Packet
	SourceName    string
	SourceKind    SourceKind
	CapturedAt    time.Time
	Length        int
	CaptureLength int
	LinkType      layers.LinkType
}

type CaptureStats struct {
	SourceName    string
	SourceKind    SourceKind
	Received      uint64
	Bytes         uint64
}

type Source interface {
	Name() string
	Kind() SourceKind
	LinkType() layers.LinkType
	Run(ctx context.Context, out chan<- RawPacket) error
	CaptureStats() (CaptureStats, error)
	Close() error
}

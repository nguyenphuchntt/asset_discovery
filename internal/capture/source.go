package capture

import (
	"context"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SourceKind string

const (
	SourceKindFile  SourceKind = "file"
	SourceKindLive  SourceKind = "live"
)

type SourceRef struct {
	Kind SourceKind
	Name string
}

type RawPacket struct {
	Packet gopacket.Packet
	Source SourceRef
}

type Source interface {
	Name() string
	Kind() SourceKind
	LinkType() layers.LinkType

	Run(ctx context.Context, out chan<- RawPacket) error

	Stats() (StatsSnapshot, error)

	Close() error
}
package capture

import "github.com/google/gopacket"

type Stats struct {
	Received int
	Dropped int
}

type Source interface {
	Packets() <-chan gopacket.Packet
	Stats() (Stats, error)
	Close() error
}
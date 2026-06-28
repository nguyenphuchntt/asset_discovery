// source.go defines the capture source contract.
//
// A Source is the only runtime component allowed to read packets from PCAP or a
// network interface. It must not send packets. Downstream packages should only
// depend on this interface, not on libpcap details.
package capture

import "github.com/google/gopacket"

type Stats struct {
	Received int
	Dropped  int
}

type Source interface {
	Packets() <-chan gopacket.Packet
	Stats() (Stats, error)
	Close() error
}

// Package analyzer turns raw gopacket packets into asset.Observation values.
//
// Each Analyzer owns one protocol surface (ARP, DHCPv4, ...) and is given
// the raw gopacket.Packet; it self-rejects by checking for its layer:
//
//	arpLayer := packet.Layer(layers.LayerTypeARP)
//	if arpLayer == nil { return nil }
//
// No intermediate "decoded" struct is built — gopacket.Packet already carries
// the layer pointers and metadata timestamps we need.
package analyzer

import (
	"github.com/google/gopacket"

	"passivediscovery/internal/asset"
)

type Analyzer interface {
	Analyze(packet gopacket.Packet) []asset.Observation
}

package analyzer

import (
	"bytes"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

// ARPAnalyzer turns ARP request/reply frames into asset.Observation values.
// Both the sender (request) and the target (reply) are emitted when their
// hardware address is usable — gratuitous ARP and zero-MAC packets are skipped.
type ARPAnalyzer struct{}

func NewARPAnalyzer() *ARPAnalyzer { return &ARPAnalyzer{} }

func (a *ARPAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	layer := packet.Layer(layers.LayerTypeARP)
	if layer == nil {
		return nil
	}
	arp, ok := layer.(*layers.ARP)
	if !ok {
		return nil
	}

	srcMAC := net.HardwareAddr(arp.SourceHwAddress)
	dstMAC := net.HardwareAddr(arp.DstHwAddress)
	srcIP := net.IP(arp.SourceProtAddress)
	dstIP := net.IP(arp.DstProtAddress)

	observedAt := packet.Metadata().Timestamp
	opName := arpOperationName(arp.Operation)

	out := make([]asset.Observation, 0, 2)
	if isUsableMAC(srcMAC) {
		out = append(out, newARPObservation(observedAt, opName, srcMAC, srcIP))
	}
	if isUsableMAC(dstMAC) && !bytes.Equal(srcMAC, dstMAC) {
		out = append(out, newARPObservation(observedAt, opName, dstMAC, dstIP))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func newARPObservation(observedAt time.Time, opName string, mac net.HardwareAddr, ip net.IP) asset.Observation {
	return asset.Observation{
		Source:      asset.SourceARP,
		ObservedAt:  observedAt,
		Identifiers: arpIdentifiers(mac, ip),
		Extra: map[string]any{
			"operation": opName,
		},
	}
}

func arpIdentifiers(mac net.HardwareAddr, ip net.IP) []asset.Identifier {
	ids := make([]asset.Identifier, 0, 2)
	if v := asset.NormalizeMACAddr(mac); v != "" {
		ids = append(ids, asset.Identifier{Type: asset.IdentifierMAC, Value: v})
	}
	if v := asset.NormalizeIPv4Addr(ip); v != "" {
		ids = append(ids, asset.Identifier{Type: asset.IdentifierIPv4, Value: v})
	}
	return ids
}

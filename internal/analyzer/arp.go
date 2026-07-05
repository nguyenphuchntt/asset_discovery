package analyzer

import (
	"bytes"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

type ARPAnalyzer struct{}

func NewARPAnalyzer() *ARPAnalyzer { return &ARPAnalyzer {} }

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
	opName := arpOperationName(arp)

	out := make([]asset.Observation, 0, 2)
	if isUsableMAC(srcMAC) {
		out = append(out, newARPObservation(observedAt, opName, srcMAC, srcIP))
	}
	if arp.Operation == layers.ARPReply &&
		isUsableMAC(dstMAC) &&
		!isBroadcastMAC(dstMAC) &&
		!bytes.Equal(srcMAC, dstMAC) {
		out = append(out, newARPObservation(observedAt, opName, dstMAC, dstIP))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func newARPObservation(observedAt time.Time, opName string, mac net.HardwareAddr, ip net.IP) asset.Observation {
	obs := asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: observedAt,
		MAC:        asset.CloneMAC(mac),
		Extra: map[string]any{
			"arp_operation":      opName,
			"arp_mac_randomized": isLocallyAdministeredMAC(mac),
		},
	}
	if ip4 := asset.NormalizeIPv4Addr(ip); ip4 != "" {
		obs.IPv4s = map[string]asset.IPEntry{ip4: {FirstSeen: observedAt, LastSeen: observedAt, IsActive: true}}
	}
	return obs
}
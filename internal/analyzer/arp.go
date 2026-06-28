package analyzer

import (
	"net"
	"passivediscovery/internal/asset"
	"passivediscovery/internal/decode"
)

type ARPAnalyzer struct{}

func NewARPAnalyzer() *ARPAnalyzer {
	return &ARPAnalyzer{}
}

func (a *ARPAnalyzer) Analyze(packet decode.DecodedPacket) []asset.Observation {
	if packet.Type != decode.PacketARP || packet.ARP == nil {
		return nil
	}

	arp := packet.ARP
	out := make([]asset.Observation, 0, 2)

	if isUsableMAC(arp.SenderMAC) {
		newObservation, ok := newARPObservation(packet, arp.SenderMAC, arp.SenderIPv4)
		if ok {
			out = append(out, newObservation)
		}
	}

	if isUsableMAC(arp.TargetMAC) {
		newObservation, ok := newARPObservation(packet, arp.TargetMAC, arp.TargetIPv4)
		if ok {
			out = append(out, newObservation)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func newARPObservation(packet decode.DecodedPacket, mac net.HardwareAddr, ip net.IP) (asset.Observation, bool) {

	arpOperation, err := arpOperationName(packet.ARP.Operation)
	if err != nil {
		return asset.Observation{}, false
	}

	return asset.Observation{
		MAC:        asset.NormalizeMACAddr(mac),
		IPv4:       asset.NormalizeIPv4Addr(ip),
		PacketType: decode.PacketARP,
		IssuedAt:   packet.SeenTime,
		Metadata: map[string]string{
			"arp.operation": arpOperation,
		},
	}, true
}
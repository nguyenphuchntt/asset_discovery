// arp.go analyzes ARP traffic for asset evidence.
//
// Responsibilities:
// - extract sender MAC/IP and valid target MAC/IP relationships;
// - classify ARP operation metadata such as request/reply/gratuitous;
// - emit observations that asset.Manager can merge into asset lifecycle;
// - reject zero/broadcast/non-usable MAC evidence.
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
	if packet.ARP == nil {
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
		Source:     asset.SourceARP,
		ObservedAt: packet.ObservedAt,
		Subject: asset.IdentitySet{
			Identifiers: arpIdentifiers(mac, ip),
		},
		Attrs: asset.AttributeSet{
			MACs:  appendIfNotEmpty(nil, asset.NormalizeMACAddr(mac)),
			IPv4s: appendIfNotEmpty(nil, asset.NormalizeIPv4Addr(ip)),
		},
		Evidence: asset.Evidence{
			Confidence: 80,
		},
		Metadata: map[string]string{
			"arp.operation": arpOperation,
		},
	}, true
}

func arpIdentifiers(mac net.HardwareAddr, ip net.IP) []asset.Identifier {
	identifiers := make([]asset.Identifier, 0, 2)
	if normalizedMAC := asset.NormalizeMACAddr(mac); normalizedMAC != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type:  asset.IdentifierMAC,
			Value: normalizedMAC,
		})
	}
	if normalizedIPv4 := asset.NormalizeIPv4Addr(ip); normalizedIPv4 != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type:  asset.IdentifierIPv4,
			Value: normalizedIPv4,
		})
	}
	return identifiers
}

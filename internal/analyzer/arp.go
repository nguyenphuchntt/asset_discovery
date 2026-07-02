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
	out := make([]asset.Observation, 0, 2) // sender/target
 
	if isUsableMAC(arp.SenderMAC) {
		out = append(out, newARPObservation(packet, arp.SenderMAC, arp.SenderIPv4))
	}
 
	if isUsableMAC(arp.TargetMAC) {
		out = append(out, newARPObservation(packet, arp.TargetMAC, arp.TargetIPv4))
	}
 
	if len(out) == 0 {
		return nil
	}
 
	return out
}

func newARPObservation(packet decode.DecodedPacket, mac net.HardwareAddr, ip net.IP) asset.Observation {
	arpOperation := arpOperationName(packet.ARP.Operation)

	return asset.Observation{
		Source: asset.SourceARP,
		ObservedAt: packet.ObservedAt,
		Subject: asset.IdentitySet{
			Identifiers: arpIdentifiers(mac, ip),
		},
		Attrs: asset.AttributeSet{
			MACs: appendMACIfUsable(nil, mac),
			IPv4s: appendIPIfUsable(nil, ip),
		},
		Evidence: asset.Evidence{
			Operation: arpOperation,
		},
	}
}

func arpIdentifiers(mac net.HardwareAddr, ip net.IP) []asset.Identifier {
	identifiers := make([]asset.Identifier, 0, 2)
	if normalizedMAC := asset.NormalizeMACAddr(mac); normalizedMAC != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type: asset.IdentifierMAC,
			Value: normalizedMAC,
		})
	}
	if normalizedIPv4 := asset.NormalizeIPv4Addr(ip); normalizedIPv4 != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type: asset.IdentifierIPv4,
			Value: normalizedIPv4,
		})
	}
	return identifiers
}

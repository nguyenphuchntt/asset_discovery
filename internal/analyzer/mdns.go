package analyzer

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

// multicast dns 
// Probing -> anyone use this name
// Listen response in multicast group UDP 5353 -> no conflict -> broadcast the claimed name

type MDNSAnalyzer struct{}

func NewMDNSAnalyzer() *MDNSAnalyzer { return &MDNSAnalyzer{} }

func (m *MDNSAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || (udp.SrcPort != 5353 && udp.DstPort != 5353) {
		return nil
	}
	dns, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok || !dns.QR { // query 
		return nil
	}

	mac, ok := ethSrcMAC(packet)
	if !ok {
		return nil
	}

	observedAt := packet.Metadata().Timestamp
	obs := asset.Observation{
		Source:     asset.SourceMDNS,
		ObservedAt: observedAt,
		MAC:        asset.CloneMAC(mac),
	}
	fillObsIPs(&obs, packet, observedAt)
	obs.Hostnames = mDNSHostnames(dns)
	obs.Services = mDNSServices(dns, observedAt)

	if !obs.Valid() {
		return nil
	}
	return []asset.Observation{obs}
}

func ethSrcMAC(packet gopacket.Packet) (net.HardwareAddr, bool) {
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok || !isUsableMAC(eth.SrcMAC) {
		return nil, false
	}
	return eth.SrcMAC, true
}

func fillObsIPs(obs *asset.Observation, packet gopacket.Packet, observedAt time.Time) {
	if v4 := packet.Layer(layers.LayerTypeIPv4); v4 != nil {
		if s := asset.NormalizeIPv4Addr(v4.(*layers.IPv4).SrcIP); s != "" {
			obs.IPv4s = map[string]asset.IPEntry{s: {FirstSeen: observedAt, LastSeen: observedAt, IsActive: true}}
		}
	}
	if v6 := packet.Layer(layers.LayerTypeIPv6); v6 != nil {
		src := v6.(*layers.IPv6).SrcIP
		if src != nil && !src.IsLinkLocalUnicast() {
			if s := asset.NormalizeIPv6Addr(src); s != "" {
				obs.IPv6s = map[string]asset.IPEntry{s: {FirstSeen: observedAt, LastSeen: observedAt, IsActive: true}}
			}
		}
	}
}

func mDNSHostnames(dns *layers.DNS) []string {
	seen := make(map[string]struct{})
	for _, r := range dns.Answers {
		if r.Type != layers.DNSTypePTR {
			continue
		}
		name := trimLocal(string(r.PTR))
		if name == "" {
			continue
		}
		seen[name] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out
}

func mDNSServices(dns *layers.DNS, observedAt time.Time) []asset.Service {
	seen := make(map[string]struct{})
	var out []asset.Service
	for _, r := range dns.Answers {
		if r.Type != layers.DNSTypeSRV || r.SRV.Port == 0 {
			continue
		}
		name := trimLocal(string(r.SRV.Name))
		key := "tcp:" + portKey(r.SRV.Port) + ":" + name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, asset.Service{
			Protocol: "tcp",
			Port:     r.SRV.Port,
			Name:     name,
			LastSeen: observedAt,
		})
	}
	return out
}
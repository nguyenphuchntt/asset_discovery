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
	ctx := DecodePacketCtx(packet)
	return m.AnalyzeCtx(&ctx)
}

func (m *MDNSAnalyzer) AnalyzeCtx(ctx *PacketCtx) []asset.Observation {
	if ctx == nil || ctx.UDP == nil || (ctx.UDP.SrcPort != 5353 && ctx.UDP.DstPort != 5353) {
		return nil
	}
	if ctx.DNS == nil || !ctx.DNS.QR {
		return nil
	}

	mac, ok := ethSrcMACFromCtx(ctx)
	if !ok {
		return nil
	}

	observedAt := ctx.ObservedAt()
	obs := asset.Observation{
		Source:     asset.SourceMDNS,
		ObservedAt: observedAt,
		MAC:        asset.CloneMAC(mac),
	}
	fillObsIPsFromCtx(&obs, ctx, observedAt)
	obs.Hostnames = mDNSHostnames(ctx.DNS)
	obs.Services = mDNSServices(ctx.DNS, observedAt)

	if !obs.Valid() {
		return nil
	}
	return []asset.Observation{obs}
}

func ethSrcMACFromCtx(ctx *PacketCtx) (net.HardwareAddr, bool) {
	if ctx == nil || ctx.Ethernet == nil || !isUsableMAC(ctx.Ethernet.SrcMAC) {
		return nil, false
	}
	return ctx.Ethernet.SrcMAC, true
}

func fillObsIPsFromCtx(obs *asset.Observation, ctx *PacketCtx, observedAt time.Time) {
	if ctx == nil {
		return
	}
	if ctx.IPv4 != nil {
		if s := asset.NormalizeIPv4Addr(ctx.IPv4.SrcIP); s != "" {
			obs.IPv4s = map[string]asset.IPEntry{s: {FirstSeen: observedAt, LastSeen: observedAt, IsActive: true}}
		}
	}
	if ctx.IPv6 != nil {
		src := ctx.IPv6.SrcIP
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
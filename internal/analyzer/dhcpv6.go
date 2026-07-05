package analyzer

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

// multicast instead of broadcast 

// stateful
// SOLICIT -> topic FF02::1:2 (replay agents and router)
// ADVERTISE -> REQUEST -> REPLY 

// stateless 
// router send Router Advertisement -> prefix + gateway 
// SLAAC -> receive prefix from RA -> generate host IP  -> 

// DUID instead of MAC 

const (
	duidTypeLL  uint16 = 3 // Link-Layer Address
	duidTypeLLT uint16 = 1 // Link-Layer Address
	duidTypeEN  uint16 = 2 // Enterprise Number
	duidTypeUUID uint16 = 4
)

type DHCPv6Analyzer struct{}

func NewDHCPv6Analyzer() *DHCPv6Analyzer { return &DHCPv6Analyzer{} }

func (d *DHCPv6Analyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	dhcp6, ok := packet.Layer(layers.LayerTypeDHCPv6).(*layers.DHCPv6)
	if !ok {
		return nil
	}
	observedAt := packet.Metadata().Timestamp
	mac, ok := dhcpv6MAC(packet)
	if !ok {
		return nil
	}

	extras := dhcpv6Extras(dhcp6)
	lease := dhcpv6IANALifetime(dhcp6)

	obs := asset.Observation{
		Source:     asset.SourceDHCPv6,
		ObservedAt: observedAt,
		MAC:        asset.CloneMAC(mac),
		Extra:      extras,
	}
	if ip6 := dhcpv6SourceIP(packet); ip6 != "" {
		obs.IPv6s = map[string]asset.IPEntry{ip6: {
			FirstSeen: observedAt,
			LastSeen:  observedAt,
			Lease:     lease,
			IsActive:  true,
		}}
	}
	if h := dhcpv6Hostname(dhcp6); h != "" {
		obs.Hostnames = []string{h}
	}
	if !obs.Valid() {
		return nil
	}
	return []asset.Observation{obs}
}

func dhcpv6MAC(packet gopacket.Packet) (net.HardwareAddr, bool) {
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		return nil, false
	}
	if !isUsableMAC(eth.SrcMAC) {
		return nil, false
	}
	return eth.SrcMAC, true
}

func dhcpv6SourceIP(packet gopacket.Packet) string {
	v6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		return ""
	}
	src := v6.SrcIP
	if src == nil || src.IsLinkLocalUnicast() {
		return ""
	}
	return asset.NormalizeIPv6Addr(src)
}

func dhcpv6Hostname(d *layers.DHCPv6) string {
	for _, opt := range d.Options {
		if opt.Code == layers.DHCPv6OptClientFQDN && len(opt.Data) > 1 {
			return trimLocal(decodeDNSName(opt.Data[1:]))
		}
	}
	return ""
}

func dhcpv6Extras(d *layers.DHCPv6) map[string]any {
	extra := map[string]any{
		"dhcpv6_message_type": d.MsgType.String(),
	}
	for _, opt := range d.Options {
		switch opt.Code {
		case layers.DHCPv6OptDomainList:
			extra["dhcpv6_domain"] = trimLocal(decodeDNSName(opt.Data))
		}
	}
	return extra
}

func dhcpv6IANALifetime(d *layers.DHCPv6) time.Duration {
	for _, opt := range d.Options {
		if opt.Code != layers.DHCPv6OptIANA || len(opt.Data) < 12 {
			continue
		}
		t2 := uint32(opt.Data[8])<<24 | uint32(opt.Data[9])<<16 |
			uint32(opt.Data[10])<<8 | uint32(opt.Data[11])
		if t2 > 0 {
			return time.Duration(t2) * time.Second
		}
		// Walk IA_Addr sub-options to find per-address valid lifetime.
		for sub := opt.Data[12:]; len(sub) >= 24; {
			addrLen := int(sub[1])<<8 | int(sub[2])
			if addrLen != 16 || 4+addrLen+8 > len(sub) {
				break
			}
			valid := uint32(sub[4+addrLen+4])<<24 |
				uint32(sub[4+addrLen+5])<<16 |
				uint32(sub[4+addrLen+6])<<8 |
				uint32(sub[4+addrLen+7])
			if valid > 0 {
				return time.Duration(valid) * time.Second
			}
			optLen := 4 + addrLen + 8 + int(sub[4+addrLen+8])<<8 | int(sub[4+addrLen+9])
			if optLen <= 0 || 4+addrLen+8+optLen > len(sub) {
				break
			}
			sub = sub[4+addrLen+8+optLen:]
		}
	}
	return 0
}

// decodeDNSName reads a DNS wire-format name from b and returns it as a
// dotted string. It stops at the first zero-length label. Compression
// pointers (RFC 1035 §4.1.4) are not handled because DHCPv6 options don't
// use them.
func decodeDNSName(b []byte) string {
	var labels []string
	for len(b) > 0 {
		n := int(b[0])
		if n == 0 {
			break
		}
		if n&0xc0 != 0 {
			break
		}
		if 1+len(labels)+n > 255 {
			break // guard against malformed input
		}
		if 1+n > len(b) {
			break
		}
		labels = append(labels, string(b[1:1+n]))
		b = b[1+n:]
	}
	if len(labels) == 0 {
		return ""
	}
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += "."
		}
		out += l
	}
	return out
}
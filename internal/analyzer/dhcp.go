package analyzer

import (
	"net"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/decode"
)

type DHCPAnalyzer struct{}

func NewDHCPAnalyzer() *DHCPAnalyzer {
	return &DHCPAnalyzer{}
}

func (d *DHCPAnalyzer) Analyze(packet decode.DecodedPacket) []asset.Observation {
	if packet.DHCPv4 == nil {
		return nil
	}

	dhcp := packet.DHCPv4
	if !isUsableMAC(dhcp.ClientMAC) {
		return nil
	}

	observation := newDHCPv4Observation(packet, dhcp.ClientMAC, selectDHCPv4IP(dhcp))

	return []asset.Observation{observation}
}

func newDHCPv4Observation(packet decode.DecodedPacket, mac net.HardwareAddr, ip net.IP) asset.Observation {
	dhcp := packet.DHCPv4

	attrs := asset.AttributeSet{
		MACs: appendMACIfUsable(nil, mac),
		IPv4s: appendIPIfUsable(nil, ip),
		Hostnames: appendIfNotEmpty(nil, dhcp.Hostname),
	}

	normalizedIP := asset.NormalizeIPv4Addr(ip)

	return asset.Observation{
		Source: asset.SourceDHCPv4,
		ObservedAt: packet.ObservedAt,
		Subject: asset.IdentitySet{
			Identifiers: dhcpv4Identifiers(mac, normalizedIP),
		},
		Attrs: attrs,
		Evidence: asset.Evidence{
			Operation: dhcpMessageTypeName(dhcp.DHCPMessageType),
			DHCPVendor: dhcp.DHCPVendor,
		},
	}
}

func dhcpv4Identifiers(mac net.HardwareAddr, normalizedIP string) []asset.Identifier {
	identifiers := make([]asset.Identifier, 0, 2)
	if normalizedMAC := asset.NormalizeMACAddr(mac); normalizedMAC != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type: asset.IdentifierMAC,
			Value: normalizedMAC,
		})
	}
	if normalizedIP != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type: asset.IdentifierIPv4,
			Value: normalizedIP,
		})
	}
	return identifiers
}

func selectDHCPv4IP(dhcp *decode.DHCPv4Info) net.IP {
	if dhcp == nil {
		return nil
	}
	if asset.NormalizeIPv4Addr(dhcp.AssignedIPv4) != "" {
		return dhcp.AssignedIPv4
	}
	if asset.NormalizeIPv4Addr(dhcp.RequestedIPv4) != "" {
		return dhcp.RequestedIPv4
	}
	if asset.NormalizeIPv4Addr(dhcp.ClientIPv4) != "" {
		return dhcp.ClientIPv4
	}
	return nil
}

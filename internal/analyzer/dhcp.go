// dhcp.go analyzes DHCP traffic for asset metadata.
//
// Responsibilities:
//   - extract client MAC, requested/assigned/client IP, hostname, vendor class,
//     DHCP message type, and later client identifiers/fingerprints;
//   - emit observations for asset.Manager;
//   - tolerate missing/malformed DHCP options;
//   - keep DHCPv6 disabled until DUID/NDP/MAC correlation policy is defined.
package analyzer

import (
	"net"
	"strconv"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/decode"
)

type DHCPAnalyzer struct{}

func NewDHCPAnalyzer() *DHCPAnalyzer {
	return &DHCPAnalyzer{}
}

func (d *DHCPAnalyzer) Analyze(packet decode.DecodedPacket) []asset.Observation {
	if packet.DHCPv6 != nil {
		// TODO: Re-enable DHCPv6 after the asset identity model for DUID,
		// NDP, and MAC correlation is finalized.
		return nil
	}

	// dhcpv4
	if packet.DHCPv4 == nil {
		return nil
	}

	dhcp := packet.DHCPv4
	if !isUsableMAC(dhcp.ClientMAC) {
		return nil
	}

	observation, ok := newDHCPv4Observation(packet, dhcp.ClientMAC, selectDHCPv4IP(dhcp))
	if !ok {
		return nil
	}

	return []asset.Observation{observation}
}

func newDHCPv4Observation(packet decode.DecodedPacket, mac net.HardwareAddr, ip net.IP) (asset.Observation, bool) {
	if packet.DHCPv4 == nil || !isUsableMAC(mac) {
		return asset.Observation{}, false
	}

	dhcp := packet.DHCPv4
	normalizedIP := asset.NormalizeIPv4Addr(ip)
	attrs := asset.AttributeSet{
		MACs:      appendIfNotEmpty(nil, asset.NormalizeMACAddr(mac)),
		IPv4s:     appendIfNotEmpty(nil, normalizedIP),
		Hostnames: appendIfNotEmpty(nil, dhcp.Hostname),
	}
	if dhcp.VendorClass != "" {
		attrs.Vendors = append(attrs.Vendors, asset.VendorHint{
			Source: "dhcp.vendor_class",
			Value:  dhcp.VendorClass,
		})
	}

	return asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: packet.ObservedAt,
		Subject: asset.IdentitySet{
			Identifiers: dhcpv4Identifiers(mac, normalizedIP),
		},
		Attrs: attrs,
		Evidence: asset.Evidence{
			Confidence: 90,
		},
		Metadata: map[string]string{
			"dhcp.message_type": strconv.FormatUint(uint64(dhcp.DHCPMessageType), 10),
		},
	}, true
}

func dhcpv4Identifiers(mac net.HardwareAddr, normalizedIP string) []asset.Identifier {
	identifiers := make([]asset.Identifier, 0, 2)
	if normalizedMAC := asset.NormalizeMACAddr(mac); normalizedMAC != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type:  asset.IdentifierMAC,
			Value: normalizedMAC,
		})
	}
	if normalizedIP != "" {
		identifiers = append(identifiers, asset.Identifier{
			Type:  asset.IdentifierIPv4,
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

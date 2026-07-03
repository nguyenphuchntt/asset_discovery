package analyzer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/utils"
)

// DHCPAnalyzer lifts DHCPv4 exchanges into asset.Observation values.
// Only packets whose client HW address is usable (non-zero 6-byte) are
// emitted, since DHCPv4 transaction IDs alone are not enough to tie a
// packet to a device.
type DHCPAnalyzer struct{}

func NewDHCPAnalyzer() *DHCPAnalyzer { return &DHCPAnalyzer{} }

func (d *DHCPAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	layer := packet.Layer(layers.LayerTypeDHCPv4)
	if layer == nil {
		return nil
	}
	dhcp, ok := layer.(*layers.DHCPv4)
	if !ok || !isUsableMAC(dhcp.ClientHWAddr) {
		return nil
	}

	observedAt := packet.Metadata().Timestamp
	ip := selectDHCPv4IP(dhcp)
	hostname := utils.DHCPv4Hostname(dhcp)

	obs := asset.Observation{
		Source:      asset.SourceDHCPv4,
		ObservedAt:  observedAt,
		Identifiers: dhcpv4Identifiers(dhcp.ClientHWAddr, ip),
		Extra: map[string]any{
			"dhcp_message_type": dhcpMessageTypeName(utils.DHCPv4MessageType(dhcp)),
			"dhcp_vendor_class": utils.DHCPv4ClassID(dhcp),
		},
	}
	if hostname != "" {
		obs.Hostnames = []string{hostname}
	}
	return []asset.Observation{obs}
}

func dhcpv4Identifiers(mac net.HardwareAddr, ip net.IP) []asset.Identifier {
	ids := make([]asset.Identifier, 0, 2)
	if v := asset.NormalizeMACAddr(mac); v != "" {
		ids = append(ids, asset.Identifier{Type: asset.IdentifierMAC, Value: v})
	}
	if v := asset.NormalizeIPv4Addr(ip); v != "" {
		ids = append(ids, asset.Identifier{Type: asset.IdentifierIPv4, Value: v})
	}
	return ids
}

// selectDHCPv4IP picks the most authoritative IP a DHCPv4 packet carries:
// assigned (from OFFER/ACK) > requested (DISCOVER/REQUEST) > ciaddr (REQUEST).
func selectDHCPv4IP(dhcp *layers.DHCPv4) net.IP {
	if dhcp == nil {
		return nil
	}
	if asset.NormalizeIPv4Addr(dhcp.YourClientIP) != "" {
		return dhcp.YourClientIP
	}
	if req := utils.DHCPv4RequestedIP(dhcp); asset.NormalizeIPv4Addr(req) != "" {
		return req
	}
	if asset.NormalizeIPv4Addr(dhcp.ClientIP) != "" {
		return dhcp.ClientIP
	}
	return nil
}

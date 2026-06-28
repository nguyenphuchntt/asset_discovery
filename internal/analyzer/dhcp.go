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
	if packet.Type == decode.PacketDHCPv6 {
		// TODO: Re-enable DHCPv6 after the asset identity model for DUID,
		// NDP, and MAC correlation is finalized.
		return nil
	}

	// dhcpv4
	if packet.Type != decode.PacketDHCPv4 || packet.DHCPv4 == nil {
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

	return asset.Observation{
		MAC:        asset.NormalizeMACAddr(mac),
		IPv4:       asset.NormalizeIPv4Addr(ip),
		Hostname:   dhcp.Hostname,
		Vendor:     dhcp.VendorClass,
		PacketType: decode.PacketDHCPv4,
		IssuedAt:   packet.SeenTime,
		Metadata: map[string]string{
			"dhcp.message_type": strconv.FormatUint(uint64(dhcp.DHCPMessageType), 10),
		},
	}, true
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

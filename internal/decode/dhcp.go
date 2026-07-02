package decode

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func decodeDHCPv4(decodedPacket *DecodedPacket, packet gopacket.Packet) bool {
	if decodedPacket == nil {
		return false
	}

	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		dhcp, ok := dhcpLayer.(*layers.DHCPv4)
		if !ok {
			return false
		}

		decodedPacket.DHCPv4 = &DHCPv4Info{
			ClientMAC:       cloneHardwareAddr(dhcp.ClientHWAddr),
			ClientIPv4:      cloneIPv4(dhcp.ClientIP),
			AssignedIPv4:    cloneIPv4(dhcp.YourClientIP),
			RequestedIPv4:   dhcpOptionIPv4(dhcp, layers.DHCPOptRequestIP),
			Hostname:        dhcpOptionString(dhcp, layers.DHCPOptHostname),
			DHCPMessageType: dhcpOptionUint16(dhcp, layers.DHCPOptMessageType),
		}

		return true
	}

	return false
}

func decodeDHCPv6(decodedPacket *DecodedPacket, packet gopacket.Packet) bool {
	if decodedPacket == nil {
		return false
	}

	if packet.Layer(layers.LayerTypeDHCPv6) != nil {
		// TODO
		return false
	}

	return false
}

func dhcpOptionString(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) string {
	option, ok := findDHCPOption(dhcp, optionType)
	if !ok || len(option.Data) == 0 {
		return ""
	}
	return string(option.Data)
}

func dhcpOptionIPv4(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) net.IP {
	option, ok := findDHCPOption(dhcp, optionType)
	if !ok || len(option.Data) < 4 {
		return nil
	}
	return cloneIPv4(net.IP(option.Data[:4]))
}

func dhcpOptionUint16(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) uint16 {
	option, ok := findDHCPOption(dhcp, optionType)
	if !ok || len(option.Data) == 0 {
		return 0
	}
	return uint16(option.Data[0])
}

func findDHCPOption(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) (layers.DHCPOption, bool) {
	if dhcp == nil {
		return layers.DHCPOption{}, false
	}
	for _, option := range dhcp.Options {
		if option.Type == optionType {
			return option, true
		}
	}
	return layers.DHCPOption{}, false
}

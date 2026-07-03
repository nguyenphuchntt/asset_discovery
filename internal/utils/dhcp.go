package utils

import (
	"net"

	"github.com/google/gopacket/layers"
)

func DHCPv4Hostname(dhcp *layers.DHCPv4) string {
	return dhcpOptionString(dhcp, layers.DHCPOptHostname)
}

func DHCPv4RequestedIP(dhcp *layers.DHCPv4) net.IP {
	return dhcpOptionIPv4(dhcp, layers.DHCPOptRequestIP)
}

func DHCPv4MessageType(dhcp *layers.DHCPv4) uint16 {
	return dhcpOptionUint16(dhcp, layers.DHCPOptMessageType)
}

// Vendor Class Identifier: Iphone, modem, router, .etc
func DHCPv4ClassID(dhcp *layers.DHCPv4) string {
	return dhcpOptionString(dhcp, layers.DHCPOptClassID)
}

func dhcpOptionString(dhcp *layers.DHCPv4, t layers.DHCPOpt) string {
	opt, ok := findDHCPOption(dhcp, t)
	if !ok || len(opt.Data) == 0 {
		return ""
	}
	return string(opt.Data)
}

func dhcpOptionIPv4(dhcp *layers.DHCPv4, t layers.DHCPOpt) net.IP {
	opt, ok := findDHCPOption(dhcp, t)
	if !ok || len(opt.Data) < 4 {
		return nil
	}
	return net.IP(opt.Data[:4])
}

func dhcpOptionUint16(dhcp *layers.DHCPv4, t layers.DHCPOpt) uint16 {
	opt, ok := findDHCPOption(dhcp, t)
	if !ok || len(opt.Data) == 0 {
		return 0
	}
	return uint16(opt.Data[0])
}

func findDHCPOption(dhcp *layers.DHCPv4, t layers.DHCPOpt) (layers.DHCPOption, bool) {
	if dhcp == nil {
		return layers.DHCPOption{}, false
	}
	for _, opt := range dhcp.Options {
		if opt.Type == t {
			return opt, true
		}
	}
	return layers.DHCPOption{}, false
}

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

func DHCPv4ClassID(dhcp *layers.DHCPv4) string {
	return dhcpOptionString(dhcp, layers.DHCPOptClassID)
}

func DHCPv4ServerID(dhcp *layers.DHCPv4) net.IP {
	return dhcpOptionIPv4(dhcp, layers.DHCPOptServerID)
}

func DHCPv4DomainName(dhcp *layers.DHCPv4) string {
	return dhcpOptionString(dhcp, layers.DHCPOptDomainName)
}

func DHCPv4DNSServers(dhcp *layers.DHCPv4) []net.IP {
	opt, ok := FindDHCPOption(dhcp, layers.DHCPOptDNS)
	if !ok || len(opt.Data) < 4 {
		return nil
	}
	count := len(opt.Data) / 4 // because data is continuously 
	out := make([]net.IP, 0, count)
	for i := 0; i < count; i++ {
		off := i * 4
		ip := make(net.IP, 4)
		copy(ip, opt.Data[off:off+4])
		out = append(out, ip)
	}
	return out
}

func DHCPv4ParamRequestList(dhcp *layers.DHCPv4) []byte {
	opt, ok := FindDHCPOption(dhcp, layers.DHCPOptParamsRequest)
	if !ok || len(opt.Data) == 0 {
		return nil
	}
	out := make([]byte, len(opt.Data))
	copy(out, opt.Data)
	return out
}

func DHCPv4RelayInfo(dhcp *layers.DHCPv4) []byte {
	opt, ok := FindDHCPOption(dhcp, 82)
	if !ok || len(opt.Data) == 0 {
		return nil
	}
	out := make([]byte, len(opt.Data))
	copy(out, opt.Data)
	return out
}

func dhcpOptionString(dhcp *layers.DHCPv4, t layers.DHCPOpt) string {
	opt, ok := FindDHCPOption(dhcp, t)
	if !ok || len(opt.Data) == 0 {
		return ""
	}
	return string(opt.Data)
}

func dhcpOptionIPv4(dhcp *layers.DHCPv4, t layers.DHCPOpt) net.IP {
	opt, ok := FindDHCPOption(dhcp, t)
	if !ok || len(opt.Data) < 4 {
		return nil
	}
	return net.IP(opt.Data[:4])
}

func dhcpOptionUint16(dhcp *layers.DHCPv4, t layers.DHCPOpt) uint16 {
	opt, ok := FindDHCPOption(dhcp, t)
	if !ok || len(opt.Data) == 0 {
		return 0
	}
	return uint16(opt.Data[0])
}

func FindDHCPOption(dhcp *layers.DHCPv4, t layers.DHCPOpt) (layers.DHCPOption, bool) {
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

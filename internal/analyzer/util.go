package analyzer

import "net"

func isUsableMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

func arpOperationName(operation uint16) string {
	switch operation {
	case 1:
		return "arp operation: request"
	case 2:
		return "arp operation: reply"
	default:
		return "arp operation: unknown"
	}
}

func appendIfNotEmpty(values []string, value string) []string {
	if value == "" {
		return values
	}
	return append(values, value)
}

func appendMACIfUsable(macs []net.HardwareAddr, mac net.HardwareAddr) []net.HardwareAddr {
	if !isUsableMAC(mac) {
		return macs
	}
	return append(macs, mac)
}

func appendIPIfUsable(ips []net.IP, ip net.IP) []net.IP {
	if ip == nil || ip.IsUnspecified() {
		return ips
	}
	return append(ips, ip)
}

func dhcpMessageTypeName(messageType uint16) string {
	switch messageType {
	case 1:
		return "dhcp operation: discover"
	case 2:
		return "dhcp operation: offer"
	case 3:
		return "dhcp operation: request"
	case 4:
		return "dhcp operation: decline"
	case 5:
		return "dhcp operation: ack"
	case 6:
		return "dhcp operation: nak"
	case 7:
		return "dhcp operation: release"
	case 8:
		return "dhcp operation: inform"
	default:
		return "dhcp operation: unknown"
	}
}

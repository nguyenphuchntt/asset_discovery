package asset

import (
	"net"
	"passivediscovery/internal/decode"
	"time"
)

type Observation struct {
	MAC string
	IPv4 string
	IPv6 string
	Hostname string
	Vendor string

	PacketType decode.PacketType

	IssuedAt time.Time
	Metadata map[string]string
}

func NormalizeMACAddr(mac net.HardwareAddr) string {
	return mac.String()
}

func NormalizeIPv4Addr(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return ip4.String()
}

func NormalizeIPv6Addr(ip net.IP) string {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return ""
	}
	return ip16.String()}

func (o Observation) Valid() bool {
	if o.MAC == "" {
		return false
	}
	return true
}
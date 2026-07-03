package asset

import (
	"net"
	"strings"
	"time"
)

type ObservationSource string

const (
	SourceEthernet ObservationSource = "ethernet"
	SourceIP ObservationSource = "ip"
	SourceARP ObservationSource = "arp"
	SourceDHCPv4 ObservationSource = "dhcpv4"
	SourceDHCPv6 ObservationSource = "dhcpv6"
	
	SourceUnknown ObservationSource = "unknown"
)

type Observation struct {
	Source ObservationSource
	ObservedAt time.Time

	Subject IdentitySet // target object
	Attrs AttributeSet

	Evidence Evidence
}

type AttributeSet struct {
	MACs []net.HardwareAddr
	IPv4s []net.IP
	IPv6s []net.IP

	Hostnames []string
	FQDNs []string

	Vendors []Vendor
	Services []Service
	Protocols []string
}

type Vendor struct {
	Source string
	Value string
}

type Service struct {
	Protocol string
	Port uint16
	Name string // https/ ssh/ tls
	Version string
}

type Evidence struct {
	Interface string
	Operation string
	DHCPVendor string
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
	return ip16.String()
}

func (o Observation) Valid() bool {
	if o.Source == "" {
		return false
	}
	if o.ObservedAt.IsZero() {
		return false
	}
	if len(o.Subject.Identifiers) == 0 {
		return false
	}
	for _, identifier := range o.Subject.Identifiers {
		if identifier.Type == "" || strings.TrimSpace(identifier.Value) == "" {
			return false
		}
	}
	return true
}

package asset

import (
	"net"
	"time"
)

type ObservationSource string

const (
	SourceEthernet ObservationSource = "ethernet"
	SourceIP       ObservationSource = "ip"
	SourceARP      ObservationSource = "arp"
	SourceDHCPv4   ObservationSource = "dhcpv4"
	SourceDHCPv6   ObservationSource = "dhcpv6"
	SourceDNS      ObservationSource = "dns"
	SourceMDNS     ObservationSource = "mdns"
	SourceLLDP     ObservationSource = "lldp"
	SourceCDP      ObservationSource = "cdp"
	SourceSSDP     ObservationSource = "ssdp"
	SourceNetBIOS  ObservationSource = "netbios"
	SourceSNMP     ObservationSource = "snmp"
	SourceHTTP     ObservationSource = "http"
	SourceTLS      ObservationSource = "tls"
	SourceSSH      ObservationSource = "ssh"
	SourceUnknown  ObservationSource = "unknown"
)

type Observation struct {
	Source     ObservationSource
	ObservedAt time.Time

	MAC net.HardwareAddr

	IPv4s map[string]IPEntry
	IPv6s map[string]IPEntry

	Hostnames []string
	Services  []Service

	// Attributes
	MACVendor  string
	DeviceType string
	Model      string
	OS         string

	Extra map[string]any
}

func (o Observation) Valid() bool {
	if o.Source == "" {
		return false
	}
	if o.ObservedAt.IsZero() {
		return false
	}
	if len(o.MAC) == 0 {
		return false
	}
	return true
}
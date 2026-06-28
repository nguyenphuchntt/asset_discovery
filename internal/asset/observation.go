// observation.go defines the evidence contract produced by analyzers.
//
// Long-term responsibilities:
//   - represent one passive observation from one packet/protocol;
//   - carry source, timestamp, identifiers, observed attributes, confidence, and
//     metadata;
//   - avoid depending on decode package types in the domain model;
//   - validate that observations have enough identity evidence before merge.
package asset

import (
	"net"
	"strings"
	"time"
)

type ObservationSource string

const (
	SourceEthernet ObservationSource = "ethernet"
	SourceIP       ObservationSource = "ip"
	SourceFlow     ObservationSource = "flow"
	SourceARP      ObservationSource = "arp"
	SourceDHCPv4   ObservationSource = "dhcpv4"
	SourceDHCPv6   ObservationSource = "dhcpv6"
	SourceNDP      ObservationSource = "ndp"
	SourceMDNS     ObservationSource = "mdns"
	SourceLLMNR    ObservationSource = "llmnr"
	SourceNBNS     ObservationSource = "nbns"
	SourceSSDP     ObservationSource = "ssdp"
	SourceLLDP     ObservationSource = "lldp"
	SourceCDP      ObservationSource = "cdp"
	SourceUnknown  ObservationSource = "unknown"
)

type Observation struct {
	Source     ObservationSource
	ObservedAt time.Time

	Subject IdentitySet
	Attrs   AttributeSet

	Evidence Evidence
	Metadata map[string]string
}

type AttributeSet struct {
	MACs      []string
	IPv4s     []string
	IPv6s     []string
	Hostnames []string
	FQDNs     []string
	Vendors   []VendorHint
	Services  []ServiceHint
	Protocols []string
}

type VendorHint struct {
	Source string
	Value  string
}

type ServiceHint struct {
	Protocol string
	Port     uint16
	Name     string
	Version  string
}

type Evidence struct {
	Confidence int
	Direction  string
	Interface  string
	CaptureID  string
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
	if o.Evidence.Confidence < 0 || o.Evidence.Confidence > 100 {
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

package asset

import (
	"net"
	"strings"
	"time"
)

// ObservationSource identifies which passive channel produced the observation.
// New sources can be added freely without changing the Asset model.
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

// Observation is what a single analyzer emits when it recognizes something in
// a decoded packet. Analyzers fill the fields that are relevant to them and
// leave the rest zero/nil.
//
// Field semantics:
//   - Identifiers: drive asset resolution (keying into the resolver index).
//     At least one is required.
//   - Hostnames: optional typed hostnames (also merged into Asset.Hostnames).
//   - Services: optional typed services (merged into Asset.Services).
//   - Extra: free-form metadata. Merged into Asset.Extra with the rules
//     documented on Asset.
type Observation struct {
	Source     ObservationSource
	ObservedAt time.Time

	Identifiers []Identifier
	Hostnames   []string
	Services    []Service
	Extra       map[string]any
}

// Valid reports whether the observation carries enough information to be
// applied to an asset.
func (o Observation) Valid() bool {
	if o.Source == "" {
		return false
	}
	if o.ObservedAt.IsZero() {
		return false
	}
	if len(o.Identifiers) == 0 {
		return false
	}
	for _, id := range o.Identifiers {
		if id.Type == "" || strings.TrimSpace(id.Value) == "" {
			return false
		}
	}
	return true
}

// Normalize*Addr convert Go's net.IP / net.HardwareAddr into canonical strings
// suitable for Identifier.Value.

func NormalizeMACAddr(mac net.HardwareAddr) string {
	if mac == nil {
		return ""
	}
	return mac.String()
}

func NormalizeIPv4Addr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ""
}

func NormalizeIPv6Addr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return v6.String()
	}
	return ""
}
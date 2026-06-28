// packet.go defines the decoded packet data model shared by analyzers.
//
// Long-term direction:
// - represent all layers that were observed, not only one packet type;
// - keep raw parsing details inside decode;
// - expose structured Ethernet/IP/transport/local-discovery metadata;
// - leave asset identity and merge decisions to analyzer/asset packages.
package decode

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type EthernetInfo struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	EtherType string
}

type NetworkInfo struct {
	Version  int
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string
}

type TransportInfo struct {
	Protocol      string
	SrcPort       uint16
	DstPort       uint16
	PayloadLength int
	TCPFlags      string
}

type ARPInfo struct {
	SenderMAC  net.HardwareAddr
	SenderIPv4 net.IP
	TargetMAC  net.HardwareAddr
	TargetIPv4 net.IP
	Operation  uint16
}

type DHCPv4Info struct {
	ClientMAC net.HardwareAddr

	ClientIPv4      net.IP
	AssignedIPv4    net.IP
	RequestedIPv4   net.IP
	Hostname        string
	DHCPMessageType uint16
	VendorClass     string
}

type DHCPv6Info struct {
	ClientDUID string
	ServerDUID string

	AssignedIPv6    net.IP
	Hostname        string
	DHCPMessageType uint16
	VendorClass     string
}

type NDPInfo struct {
	TargetIPv6  net.IP
	SourceMAC   net.HardwareAddr
	TargetMAC   net.HardwareAddr
	MessageType string
}

type NameInfo struct {
	Protocol string
	Name     string
	IPv4s    []net.IP
	IPv6s    []net.IP
}

type DiscoveryInfo struct {
	Protocol string
	Service  string
	Hostname string
	Metadata map[string]string
}

type DecodedPacket struct {
	ObservedAt time.Time

	Ethernet   *EthernetInfo
	Network    *NetworkInfo
	Transport  *TransportInfo
	ARP        *ARPInfo
	DHCPv4     *DHCPv4Info
	DHCPv6     *DHCPv6Info
	NDP        *NDPInfo
	LocalNames []NameInfo
	Discovery  []DiscoveryInfo
	Errors     []string
}

func (dp DecodedPacket) HasDecodedData() bool {
	return dp.Ethernet != nil ||
		dp.Network != nil ||
		dp.Transport != nil ||
		dp.ARP != nil ||
		dp.DHCPv4 != nil ||
		dp.DHCPv6 != nil ||
		dp.NDP != nil ||
		len(dp.LocalNames) > 0 ||
		len(dp.Discovery) > 0
}

func (dp DecodedPacket) String() string {
	layers := make([]string, 0, 6)
	if dp.Ethernet != nil {
		layers = append(layers, "ethernet")
	}
	if dp.Network != nil {
		layers = append(layers, fmt.Sprintf("ip%d", dp.Network.Version))
	}
	if dp.Transport != nil {
		layers = append(layers, strings.ToLower(dp.Transport.Protocol))
	}
	if dp.ARP != nil {
		layers = append(layers, "arp")
	}
	if dp.DHCPv4 != nil {
		layers = append(layers, "dhcpv4")
	}
	if dp.DHCPv6 != nil {
		layers = append(layers, "dhcpv6")
	}
	if dp.NDP != nil {
		layers = append(layers, "ndp")
	}
	if len(layers) == 0 {
		layers = append(layers, "unknown")
	}

	return fmt.Sprintf(
		"Layers=%s ObservedAt=%v",
		strings.Join(layers, ","),
		dp.ObservedAt,
	)
}

package decode

import (
	"fmt"
	"net"
	"time"
)

type PacketType string

const (
	PacketARP    PacketType = "arp"
	PacketDHCPv4 PacketType = "dhcpv4"
	PacketNDP    PacketType = "ndp"
	PacketDHCPv6 PacketType = "dhcpv6"
)

type EthernetInfo struct {
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
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
	ClientMAC  net.HardwareAddr
	ClientDUID string
	ServerDUID string

	AssignedIPv6    net.IP
	Hostname        string
	DHCPMessageType uint16
	VendorClass     string
}

type DecodedPacket struct {
	Type     PacketType
	SeenTime time.Time

	Ethernet *EthernetInfo
	ARP      *ARPInfo
	DHCPv4   *DHCPv4Info
	DHCPv6   *DHCPv6Info
}

func (dp DecodedPacket) String() string {
	return fmt.Sprintf(
		"Type=%v Seen=%v",
		dp.Type,
		dp.SeenTime,
	)
}

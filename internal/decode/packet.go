package decode

import (
	"net"
	"time"
)

type PacketType string

const (
	PacketARP  PacketType = "arp"
	PacketDHCP PacketType = "dhcp"
)

type EthernetInfo struct {
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
}

type ARPInfo struct {
	SenderMAC net.HardwareAddr
	SenderIP  net.IP
	TargetMAC net.HardwareAddr
	TargetIP  net.IP
	Operation uint16
}

type DHCPInfo struct {
	ClientMAC net.HardwareAddr
}

type DecodedPacket struct {
	Type     PacketType
	SeenTime time.Time

	Ethernet *EthernetInfo
	ARP      *ARPInfo
	DHCP     *DHCPInfo
}

package decode

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type EthernetInfo struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	EtherType layers.EthernetType
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
}

type DecodedPacket struct {
	ObservedAt time.Time

	Ethernet  *EthernetInfo
	Network   *NetworkInfo
	Transport *TransportInfo
	ARP       *ARPInfo
	DHCPv4    *DHCPv4Info
}

func (dp DecodedPacket) HasDecodedData() bool {
	return dp.Ethernet != nil ||
		dp.Network != nil ||
		dp.Transport != nil ||
		dp.ARP != nil ||
		dp.DHCPv4 != nil
}

func (dp DecodedPacket) String() string {
	return fmt.Sprintf("Decoded a packet at=%v", dp.ObservedAt)
}

package decode

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Decoder struct{}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Decode(packet gopacket.Packet) (DecodedPacket, bool) {
	if packet == nil {
		return DecodedPacket{}, false
	}

	decoded := newDecodedPacket(packet)

	// ARP
	if decodeARP(&decoded, packet) {
		return decoded, true
	}

	// DHCP
	if decodeDHCP(&decoded, packet) {
		return decoded, true
	}
	// ...

	return DecodedPacket{}, false
}

func newDecodedPacket(packet gopacket.Packet) DecodedPacket {
	decoded := DecodedPacket{
		SeenTime: packet.Metadata().Timestamp,
	}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		if ethernet, ok := ethernetLayer.(*layers.Ethernet); ok {
			decoded.Ethernet = &EthernetInfo{
				SrcMAC: cloneHardwareAddr(ethernet.SrcMAC),
				DstMAC: cloneHardwareAddr(ethernet.DstMAC),
			}
		}
	}

	return decoded
}

func decodeARP(decodedPacket *DecodedPacket, packet gopacket.Packet) bool {
	if decodedPacket == nil {
		return false
	}

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, ok := arpLayer.(*layers.ARP) // type assertion
		if !ok {
			return false
		}

		decodedPacket.Type = PacketARP
		decodedPacket.ARP = &ARPInfo{
			SenderMAC: cloneHardwareAddr(arp.SourceHwAddress),
			SenderIP:  cloneIP(arp.SourceProtAddress),
			TargetMAC: cloneHardwareAddr(arp.DstHwAddress),
			TargetIP:  cloneIP(arp.DstProtAddress),
			Operation: arp.Operation, // 1 request | 2 reply
		}

		return true
	}

	return false
}

func decodeDHCP(decodedPacket *DecodedPacket, packet gopacket.Packet) bool {
	if decodedPacket == nil {
		return false
	}

	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		dhcp, ok := dhcpLayer.(*layers.DHCPv4)
		if !ok {
			return false
		}

		decodedPacket.Type = PacketDHCP
		decodedPacket.DHCP = &DHCPInfo{
			ClientMAC: cloneHardwareAddr(dhcp.ClientHWAddr),
		}

		return true
	}

	return false
}

func cloneHardwareAddr(addr net.HardwareAddr) net.HardwareAddr {
	if addr == nil {
		return nil
	}
	return append(net.HardwareAddr(nil), addr...) // unpack
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

// decoder.go converts gopacket.Packet values into DecodedPacket values.
//
// Responsibilities:
// - parse known layers safely without panics on malformed packets;
// - preserve capture timestamp and link-layer metadata;
// - decode ARP/DHCP today and expand to multi-layer packet models later;
// - keep decoding separate from asset observation/merge policy.
package decode

import (
	"net"
	"strings"

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
	decodeNetwork(&decoded, packet)
	decodeTransport(&decoded, packet)
	decodeARP(&decoded, packet)
	decodeDHCP(&decoded, packet)

	return decoded, decoded.HasDecodedData()
}

func newDecodedPacket(packet gopacket.Packet) DecodedPacket {
	decoded := DecodedPacket{
		ObservedAt: packet.Metadata().Timestamp,
	}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		if ethernet, ok := ethernetLayer.(*layers.Ethernet); ok {
			decoded.Ethernet = &EthernetInfo{
				SrcMAC:    cloneHardwareAddr(ethernet.SrcMAC),
				DstMAC:    cloneHardwareAddr(ethernet.DstMAC),
				EtherType: ethernet.EthernetType.String(),
			}
		}
	}

	return decoded
}

func decodeNetwork(decodedPacket *DecodedPacket, packet gopacket.Packet) {
	if decodedPacket == nil {
		return
	}

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, ok := ipv4Layer.(*layers.IPv4)
		if !ok {
			return
		}
		decodedPacket.Network = &NetworkInfo{
			Version:  4,
			SrcIP:    cloneIP(ipv4.SrcIP),
			DstIP:    cloneIP(ipv4.DstIP),
			Protocol: ipv4.Protocol.String(),
		}
		return
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, ok := ipv6Layer.(*layers.IPv6)
		if !ok {
			return
		}
		decodedPacket.Network = &NetworkInfo{
			Version:  6,
			SrcIP:    cloneIP(ipv6.SrcIP),
			DstIP:    cloneIP(ipv6.DstIP),
			Protocol: ipv6.NextHeader.String(),
		}
	}
}

func decodeTransport(decodedPacket *DecodedPacket, packet gopacket.Packet) {
	if decodedPacket == nil {
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return
		}
		decodedPacket.Transport = &TransportInfo{
			Protocol:      "tcp",
			SrcPort:       uint16(tcp.SrcPort),
			DstPort:       uint16(tcp.DstPort),
			PayloadLength: len(tcp.Payload),
			TCPFlags:      tcpFlags(tcp),
		}
		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return
		}
		decodedPacket.Transport = &TransportInfo{
			Protocol:      "udp",
			SrcPort:       uint16(udp.SrcPort),
			DstPort:       uint16(udp.DstPort),
			PayloadLength: len(udp.Payload),
		}
	}
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

		decodedPacket.ARP = &ARPInfo{
			SenderMAC:  cloneHardwareAddr(arp.SourceHwAddress),
			SenderIPv4: cloneIPv4(arp.SourceProtAddress),
			TargetMAC:  cloneHardwareAddr(arp.DstHwAddress),
			TargetIPv4: cloneIPv4(arp.DstProtAddress),
			Operation:  arp.Operation, // 1 request | 2 reply
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

		decodedPacket.DHCPv4 = &DHCPv4Info{
			ClientMAC:       cloneHardwareAddr(dhcp.ClientHWAddr),
			ClientIPv4:      cloneIPv4(dhcp.ClientIP),
			AssignedIPv4:    cloneIPv4(dhcp.YourClientIP),
			RequestedIPv4:   dhcpOptionIPv4(dhcp, layers.DHCPOptRequestIP),
			Hostname:        dhcpOptionString(dhcp, layers.DHCPOptHostname),
			DHCPMessageType: dhcpOptionUint16(dhcp, layers.DHCPOptMessageType),
			VendorClass:     dhcpOptionString(dhcp, layers.DHCPOptClassID),
		}

		return true
	}

	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6); dhcpLayer != nil {
		// TODO: Re-enable DHCPv6 after the asset identity model for DUID,
		// NDP, and MAC correlation is finalized.
		return false
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

func cloneIPv4(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return append(net.IP(nil), ip4...)
}

func dhcpOptionString(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) string {
	option, ok := findDHCPOption(dhcp, optionType)
	if !ok || len(option.Data) == 0 {
		return ""
	}
	return string(option.Data)
}

func dhcpOptionIPv4(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) net.IP {
	option, ok := findDHCPOption(dhcp, optionType)
	if !ok || len(option.Data) < 4 {
		return nil
	}
	return cloneIPv4(net.IP(option.Data[:4]))
}

func dhcpOptionUint16(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) uint16 {
	option, ok := findDHCPOption(dhcp, optionType)
	if !ok || len(option.Data) == 0 {
		return 0
	}
	return uint16(option.Data[0])
}

func findDHCPOption(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) (layers.DHCPOption, bool) {
	if dhcp == nil {
		return layers.DHCPOption{}, false
	}
	for _, option := range dhcp.Options {
		if option.Type == optionType {
			return option, true
		}
	}
	return layers.DHCPOption{}, false
}

func tcpFlags(tcp *layers.TCP) string {
	if tcp == nil {
		return ""
	}
	flags := make([]string, 0, 6)
	if tcp.SYN {
		flags = append(flags, "syn")
	}
	if tcp.ACK {
		flags = append(flags, "ack")
	}
	if tcp.FIN {
		flags = append(flags, "fin")
	}
	if tcp.RST {
		flags = append(flags, "rst")
	}
	if tcp.PSH {
		flags = append(flags, "psh")
	}
	if tcp.URG {
		flags = append(flags, "urg")
	}
	return strings.Join(flags, ",")
}

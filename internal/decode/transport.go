package decode

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
			Protocol: "tcp",
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			PayloadLength: len(tcp.Payload),
			TCPFlags: tcpFlags(tcp),
		}
		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return
		}
		decodedPacket.Transport = &TransportInfo{
			Protocol: "udp",
			SrcPort: uint16(udp.SrcPort),
			DstPort: uint16(udp.DstPort),
			PayloadLength: len(udp.Payload),
		}
	}
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

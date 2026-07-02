package decode

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
			Version: 4,
			SrcIP: cloneIP(ipv4.SrcIP),
			DstIP: cloneIP(ipv4.DstIP),
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
			Version: 6,
			SrcIP: cloneIP(ipv6.SrcIP),
			DstIP: cloneIP(ipv6.DstIP),
			Protocol: ipv6.NextHeader.String(),
		}
	}
}

package decode

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func newDecodedPacket(packet gopacket.Packet) DecodedPacket {
	decoded := DecodedPacket{}
	if metadata := packet.Metadata(); metadata != nil {
		decoded.ObservedAt = metadata.Timestamp
	}
	return decoded
}

func decodeEthernet(decodedPacket *DecodedPacket, packet gopacket.Packet) {
	if decodedPacket == nil {
		return
	}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		if ethernet, ok := ethernetLayer.(*layers.Ethernet); ok {
			decodedPacket.Ethernet = &EthernetInfo{
				SrcMAC:    cloneHardwareAddr(ethernet.SrcMAC),
				DstMAC:    cloneHardwareAddr(ethernet.DstMAC),
				EtherType: ethernet.EthernetType,
			}
		}
	}
}

package decode

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func decodeARP(decodedPacket *DecodedPacket, packet gopacket.Packet) bool {
	if decodedPacket == nil {
		return false
	}

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			return false
		}

		decodedPacket.ARP = &ARPInfo{
			SenderMAC:  cloneHardwareAddr(arp.SourceHwAddress),
			SenderIPv4: cloneIPv4(arp.SourceProtAddress),
			TargetMAC:  cloneHardwareAddr(arp.DstHwAddress),
			TargetIPv4: cloneIPv4(arp.DstProtAddress),
			Operation:  arp.Operation,
		}

		return true
	}

	return false
}

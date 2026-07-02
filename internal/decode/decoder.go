package decode

import (
	"github.com/google/gopacket"
)

type PacketDecoder interface {
	Decode(packet gopacket.Packet) (DecodedPacket, bool)
}

type Decoder struct{}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Decode(packet gopacket.Packet) (DecodedPacket, bool) {
	if packet == nil {
		return DecodedPacket{}, false
	}

	decoded := newDecodedPacket(packet)
	decodeEthernet(&decoded, packet)
	decodeARP(&decoded, packet)
	decodeNetwork(&decoded, packet)
	decodeTransport(&decoded, packet)
	decodeDHCPv4(&decoded, packet)
	decodeDHCPv6(&decoded, packet)

	return decoded, decoded.HasDecodedData()
}

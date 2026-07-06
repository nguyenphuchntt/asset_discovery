package analyzer

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketCtx struct {
	Packet   gopacket.Packet
	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	IPv6     *layers.IPv6
	ARP      *layers.ARP
	DHCPv4   *layers.DHCPv4
	DHCPv6   *layers.DHCPv6
	UDP      *layers.UDP
	TCP      *layers.TCP
	DNS      *layers.DNS
}

func (c *PacketCtx) ObservedAt() time.Time {
	ts := c.Packet.Metadata().Timestamp
	if ts.IsZero() {
		return time.Now()
	}
	return ts
}

func DecodePacketCtx(pkt gopacket.Packet) PacketCtx {
	if pkt == nil {
		return PacketCtx{}
	}
	ctx := PacketCtx{Packet: pkt}

	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		ctx.Ethernet = eth.(*layers.Ethernet)
	}
	if v4 := pkt.Layer(layers.LayerTypeIPv4); v4 != nil {
		ctx.IPv4 = v4.(*layers.IPv4)
	}
	if v6 := pkt.Layer(layers.LayerTypeIPv6); v6 != nil {
		ctx.IPv6 = v6.(*layers.IPv6)
	}
	if arp := pkt.Layer(layers.LayerTypeARP); arp != nil {
		ctx.ARP = arp.(*layers.ARP)
	}
	if dhcp4 := pkt.Layer(layers.LayerTypeDHCPv4); dhcp4 != nil {
		ctx.DHCPv4 = dhcp4.(*layers.DHCPv4)
	}
	if dhcp6 := pkt.Layer(layers.LayerTypeDHCPv6); dhcp6 != nil {
		ctx.DHCPv6 = dhcp6.(*layers.DHCPv6)
	}
	if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
		ctx.UDP = udp.(*layers.UDP)
	}
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		ctx.TCP = tcp.(*layers.TCP)
	}
	if dns := pkt.Layer(layers.LayerTypeDNS); dns != nil {
		ctx.DNS = dns.(*layers.DNS)
	}

	return ctx
}

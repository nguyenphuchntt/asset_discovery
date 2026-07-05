// Package helpers provides shared utilities for tests across the project.
package helpers

import (
	"crypto/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RandMAC returns a random unicast MAC address with the multicast bit cleared
// and the locally-administered bit cleared (so it looks like a real NIC).
func RandMAC() net.HardwareAddr {
	mac := make(net.HardwareAddr, 6)
	_, _ = rand.Read(mac)
	mac[0] &= 0xFE // clear multicast bit
	mac[0] &= 0xFD // clear locally-administered bit for realism
	return mac
}

// RandMACLocallyAdministered returns a random MAC with the locally-administered
// bit set — useful to test "randomized MAC" detection.
func RandMACLocallyAdministered() net.HardwareAddr {
	mac := RandMAC()
	mac[0] |= 0x02
	return mac
}

// BroadcastMAC returns the Ethernet broadcast address ff:ff:ff:ff:ff:ff.
func BroadcastMAC() net.HardwareAddr {
	return net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
}

// ZeroMAC returns an all-zero MAC address.
func ZeroMAC() net.HardwareAddr {
	return net.HardwareAddr{0, 0, 0, 0, 0, 0}
}

// RandIPv4 returns a random IPv4 in 10.0.0.0/8.
func RandIPv4() net.IP {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	b[0] = 10
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// IPv4 returns a fixed IPv4 for deterministic tests.
func IPv4(a, b, c, d byte) net.IP {
	return net.IPv4(a, b, c, d)
}

// IPv6 returns a fixed IPv6 for deterministic tests.
func IPv6(bs ...byte) net.IP {
	return net.IP(bs)
}

// ARPPacket builds a synthetic ARP packet for analyzer tests.
//
//   - op: layers.ARPRequest or layers.ARPReply
//   - srcMAC, dstMAC: 6-byte MAC addresses
//   - srcIP, dstIP: 4-byte IPv4
func ARPPacket(op uint16, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, arp,
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

// ARPPacketWithIP builds an ARP packet where the given srcMAC uses the given
// srcIP. Caller passes dst MAC/IP directly.
func ARPPacketWithIP(op uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) gopacket.Packet {
	return ARPPacket(op, srcMAC, dstMAC, srcIP, dstIP)
}
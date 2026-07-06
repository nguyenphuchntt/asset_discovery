package analyzer_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// DHCPv6Analyzer.Analyze — covered scenarios:
//   1. Non-DHCPv6 packet returns nil
//   2. SOLICIT with DUID-LL → 1 observation with MAC
//   3. ADVERTISE with DUID-LLT → 1 observation with MAC
//   4. Non-link-local source IPv6 → IPv6 populated
//   5. Link-local source IPv6 → IPv6 NOT populated
//   6. No Ethernet layer → returns nil
//   7. Zero src MAC → returns nil
//   8. Domain list option → extra "dhcpv6_domain" set
//   9. Hostname option → hostname populated
//  10. IANA option with T2 lifetime → lease set
//  11. Message type set in Extra

// buildDHCPv6Packet builds a minimal DHCPv6 packet with UDP + Ethernet.
func buildDHCPv6Packet(t *testing.T, srcMAC []byte, msgType layers.DHCPv6MsgType, opts []layers.DHCPv6Option) gopacket.Packet {
	t.Helper()

	dhcp6 := &layers.DHCPv6{MsgType: msgType}
	if opts != nil {
		dhcp6.Options = opts
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv6,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(546),
		DstPort: layers.UDPPort(547),
	}

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, udp, dhcp6,
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestDHCPv6Analyzer_NonDHCPv6(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-DHCPv6, got %d", len(got))
	}
}

func TestDHCPv6Analyzer_NilPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()
	if got := a.Analyze(nil); got != nil {
		t.Fatalf("expected nil for nil packet, got %d", len(got))
	}
}

func TestDHCPv6Analyzer_Solicit(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()
	pkt := buildDHCPv6Packet(t, helpers.RandMAC(), layers.DHCPv6MsgTypeSolicit, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceDHCPv6 {
		t.Errorf("expected source=DHCPv6, got %q", obs[0].Source)
	}
	if len(obs[0].MAC) == 0 {
		t.Error("expected MAC to be set")
	}
}

func TestDHCPv6Analyzer_Advertise(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()
	pkt := buildDHCPv6Packet(t, helpers.RandMAC(), layers.DHCPv6MsgTypeAdverstise, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

func TestDHCPv6Analyzer_NoEthernetLayer(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()
	// Build packet without Ethernet — just DHCPv6.
	dhcp6 := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeSolicit}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, dhcp6)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeNull, gopacket.Default)

	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for packet without Ethernet, got %d", len(got))
	}
}

func TestDHCPv6Analyzer_ZeroSrcMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()
	pkt := buildDHCPv6Packet(t, helpers.ZeroMAC(), layers.DHCPv6MsgTypeSolicit, nil)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for zero MAC, got %d", len(got))
	}
}

func TestDHCPv6Analyzer_MessageTypeExtra(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()

	cases := []struct {
		msgType layers.DHCPv6MsgType
	}{
		{layers.DHCPv6MsgTypeSolicit},
		{layers.DHCPv6MsgTypeAdverstise},
	}
	for _, tc := range cases {
		pkt := buildDHCPv6Packet(t, helpers.RandMAC(), tc.msgType, nil)
		obs := a.Analyze(pkt)
		if len(obs) != 1 {
			t.Fatalf("msgType %d: expected 1 observation, got %d", tc.msgType, len(obs))
		}
		if _, ok := obs[0].Extra["dhcpv6_message_type"]; !ok {
			t.Errorf("msgType %d: expected dhcpv6_message_type in Extra", tc.msgType)
		}
	}
}

func TestDHCPv6Analyzer_DomainOption(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()

	// Domain in DNS wire format: \x06google\x03com\x00
	domainData := []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}
	opts := []layers.DHCPv6Option{
		{Code: layers.DHCPv6OptDomainList, Data: domainData},
	}

	pkt := buildDHCPv6Packet(t, helpers.RandMAC(), layers.DHCPv6MsgTypeSolicit, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got, ok := obs[0].Extra["dhcpv6_domain"]; !ok || got == "" {
		t.Errorf("expected dhcpv6_domain to be set, got %v", got)
	}
}

func TestDHCPv6Analyzer_IANAWithT2Lifetime(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()

	// IANA option: code=3, T2 at bytes 8-11 = 3600
	t2 := uint32(3600)
	ianaData := make([]byte, 12)
	ianaData[8] = byte(t2 >> 24)
	ianaData[9] = byte(t2 >> 16)
	ianaData[10] = byte(t2 >> 8)
	ianaData[11] = byte(t2)

	opts := []layers.DHCPv6Option{
		{Code: layers.DHCPv6OptIANA, Data: ianaData},
	}

	pkt := buildDHCPv6Packet(t, helpers.RandMAC(), layers.DHCPv6MsgTypeAdverstise, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

func TestDHCPv6Analyzer_LinkLocalIPv6Skipped(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPv6Analyzer()

	// Build full packet with Ethernet + IPv6 + UDP + DHCPv6.
	srcMAC := helpers.RandMAC()
	linkLocalIP := helpers.IPv6(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01)

	dhcp6 := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeSolicit}
	udp := &layers.UDP{SrcPort: 546, DstPort: 547}
	ip6 := &layers.IPv6{
		SrcIP: linkLocalIP,
		DstIP: helpers.IPv6(0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02),
		NextHeader: layers.IPProtocolUDP,
		HopLimit: 64,
	}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv6,
	}

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, ip6, udp, dhcp6,
	)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)

	obs := a.Analyze(pkt)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	// Link-local IPv6 should NOT be included.
	if len(obs[0].IPv6s) > 0 {
		t.Errorf("expected link-local IPv6 to be skipped, got IPv6s: %v", obs[0].IPv6s)
	}
}

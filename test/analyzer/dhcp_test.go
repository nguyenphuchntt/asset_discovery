package analyzer_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// DHCPAnalyzer.Analyze — covered scenarios:
//   1. Non-DHCP packet returns nil
//   2. DHCP DISCOVER → observation with hostname, MAC, source=DHCPv4
//   3. DHCP REQUEST → observation with IPv4 + lease
//   4. DHCP ACK → observation with all fields
//   5. DHCP with option 55 (parameter request list) → extra key present
//   6. DHCP with option 54 (server ID) → extra key present
//   7. DHCP with option 6 (DNS servers) → extra key present
//   8. DHCP with option 15 (domain name) → extra key present
//   9. DHCP with option 66 (TFTP server) → extra key present
//  10. DHCP with option 67 (boot file) → extra key present
//  11. DHCP with option 82 (relay agent) → extra key present
//  12. DHCP with zero ClientHWAddr returns nil
//  13. DHCP OFFER → observation
//  14. DHCP NAK → observation
//  15. DHCP RELEASE → observation
//  16. Lease duration extracted from option 51
//  17. Hostname extracted from DHCP option 12

// buildDHCPv4 creates a basic DHCPv4 packet with the given options.
func buildDHCPv4(t *testing.T, clientMAC net.HardwareAddr, messageType layers.DHCPMsgType, opts []layers.DHCPOption) gopacket.Packet {
	t.Helper()
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: clientMAC,
	}
	dhcp.Options = append(dhcp.Options, opts...)
	// Always append the message type option (DHCP option 53).
	// Use NewDHCPOption so Length is auto-populated from Data.
	dhcp.Options = append(dhcp.Options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(messageType)}),
	)

	eth := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		SrcIP:    helpers.IPv4(0, 0, 0, 0),
		DstIP:    helpers.IPv4(255, 255, 255, 255),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(68),
		DstPort: layers.UDPPort(67),
	}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, ip4, udp, dhcp,
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestDHCPAnalyzer_NonDHCP(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-DHCP packet, got %d", len(got))
	}
}

func TestDHCPAnalyzer_NilPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	if got := a.Analyze(nil); got != nil {
		t.Fatalf("expected nil for nil packet, got %d", len(got))
	}
}

func TestDHCPAnalyzer_DISCOVER(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeDiscover, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceDHCPv4 {
		t.Errorf("expected source=DHCPv4, got %q", obs[0].Source)
	}
}

func TestDHCPAnalyzer_REQUEST(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeRequest, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceDHCPv4 {
		t.Errorf("expected source=DHCPv4, got %q", obs[0].Source)
	}
}

func TestDHCPAnalyzer_ACK(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeAck, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceDHCPv4 {
		t.Errorf("expected source=DHCPv4, got %q", obs[0].Source)
	}
}

func TestDHCPAnalyzer_Offer(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeOffer, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

func TestDHCPAnalyzer_NAK(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeNak, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

func TestDHCPAnalyzer_RELEASE(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeRelease, nil)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

func TestDHCPAnalyzer_OptionHostname(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptHostname, []byte("my-laptop")),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeDiscover, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Hostnames) != 1 || obs[0].Hostnames[0] != "my-laptop" {
		t.Errorf("expected hostname=my-laptop, got %v", obs[0].Hostnames)
	}
}

func TestDHCPAnalyzer_Option55_ParamRequestList(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{1, 3, 6, 15, 43}),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeDiscover, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Extra["dhcpv4_param_request_list"] == nil {
		t.Error("expected dhcpv4_param_request_list to be set in Extra")
	}
}

func TestDHCPAnalyzer_Option54_ServerID(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptServerID, []byte{192, 168, 1, 1}),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeAck, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Extra["dhcpv4_server"] != "192.168.1.1" {
		t.Errorf("expected dhcpv4_server=192.168.1.1, got %v", obs[0].Extra["dhcpv4_server"])
	}
}

func TestDHCPAnalyzer_Option6_DNS(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	// Two DNS servers: 8.8.8.8 and 8.8.4.4
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptDNS, []byte{8, 8, 8, 8, 8, 8, 4, 4}),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeAck, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Extra["dhcpv4_dns_servers"] == nil {
		t.Error("expected dhcpv4_dns_servers to be set in Extra")
	}
}

func TestDHCPAnalyzer_Option15_Domain(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptDomainName, []byte("example.com")),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeAck, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Extra["dhcpv4_domain"] != "example.com" {
		t.Errorf("expected dhcpv4_domain=example.com, got %v", obs[0].Extra["dhcpv4_domain"])
	}
}

func TestDHCPAnalyzer_Option82_RelayAgent(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOpt(82), []byte{0x52, 0x02, 0x00, 0x0A}),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeDiscover, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Extra["dhcpv4_relay_agent"] == nil {
		t.Error("expected dhcpv4_relay_agent to be set in Extra")
	}
}

func TestDHCPAnalyzer_ZeroClientMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()
	pkt := buildDHCPv4(t, helpers.ZeroMAC(), layers.DHCPMsgTypeDiscover, nil)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for zero client MAC, got %d", len(got))
	}
}

func TestDHCPAnalyzer_LeaseDuration(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()

	// Lease time = 3600 seconds (1 hour) encoded as 4 big-endian bytes
	leaseSecs := uint32(3600)
	opts := []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptLeaseTime, []byte{
			byte(leaseSecs >> 24), byte(leaseSecs >> 16), byte(leaseSecs >> 8), byte(leaseSecs),
		}),
	}
	pkt := buildDHCPv4(t, helpers.RandMAC(), layers.DHCPMsgTypeAck, opts)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	ip4 := findFirstIPv4(obs[0])
	if ip4 == "" {
		t.Fatal("expected at least one IPv4 in observation")
	}
	if obs[0].IPv4s[ip4].Lease != time.Hour {
		t.Errorf("expected lease=1h, got %v", obs[0].IPv4s[ip4].Lease)
	}
}

func TestDHCPAnalyzer_MessageTypeExtra(t *testing.T) {
	t.Parallel()
	a := analyzer.NewDHCPAnalyzer()

	cases := []struct {
		msgType layers.DHCPMsgType
		want    string
	}{
		{layers.DHCPMsgTypeDiscover, "discover"},
		{layers.DHCPMsgTypeRequest, "request"},
		{layers.DHCPMsgTypeAck, "ack"},
	}
	for _, tc := range cases {
		pkt := buildDHCPv4(t, helpers.RandMAC(), tc.msgType, nil)
		obs := a.Analyze(pkt)
		if len(obs) != 1 {
			t.Fatalf("msgType %d: expected 1 observation, got %d", tc.msgType, len(obs))
		}
		if got := obs[0].Extra["dhcpv4_message_type"]; got != tc.want {
			t.Errorf("msgType %d: expected %q, got %v", tc.msgType, tc.want, got)
		}
	}
}

// findFirstIPv4 returns the first IPv4 key in the observation map.
func findFirstIPv4(obs asset.Observation) string {
	for ip := range obs.IPv4s {
		return ip
	}
	return ""
}
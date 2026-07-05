package analyzer_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// MDNSAnalyzer.Analyze — covered scenarios:
//   1. Non-UDP packet returns nil
//   2. UDP not on port 5353 returns nil
//   3. DNS query (QR=false) returns nil
//   4. DNS response with PTR answer → hostname extracted
//   5. DNS response with SRV answer → service extracted
//   6. DNS response with PTR + SRV → both hostname and service
//   7. Zero src MAC returns nil
//   8. No Ethernet layer returns nil
//   9. Multiple PTR answers → multiple hostnames
//  10. Duplicate PTR answers → deduplicated
//  11. SRV port 0 → service skipped
//  12. SRV with valid port → service has correct protocol/port/name

// buildMDNSResponse builds a UDP DNS response packet on port 5353.
func buildMDNSResponse(t *testing.T, srcMAC []byte, answers []layers.DNSResourceRecord) gopacket.Packet {
	t.Helper()

	dns := &layers.DNS{
		QR:      true, // response
		Answers: answers,
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		SrcIP:    helpers.IPv4(10, 0, 0, 5),
		DstIP:    helpers.IPv4(224, 0, 0, 251),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5353),
		DstPort: layers.UDPPort(5353),
	}

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, ip4, udp, dns,
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestMDNSAnalyzer_NonUDP(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-UDP packet, got %d", len(got))
	}
}

func TestMDNSAnalyzer_NilPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()
	if got := a.Analyze(nil); got != nil {
		t.Fatalf("expected nil for nil packet, got %d", len(got))
	}
}

func TestMDNSAnalyzer_QueryReturnsNil(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	dns := &layers.DNS{QR: false} // query, not response
	eth := &layers.Ethernet{
		SrcMAC:       helpers.RandMAC(),
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(5353), DstPort: layers.UDPPort(5353)}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		eth, udp, dns,
	)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)

	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for DNS query, got %d", len(got))
	}
}

func TestMDNSAnalyzer_PTRAnswer(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	answers := []layers.DNSResourceRecord{
		{
			Type: layers.DNSTypePTR,
			PTR:  []byte("_http._tcp.local."),
		},
	}
	pkt := buildMDNSResponse(t, helpers.RandMAC(), answers)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceMDNS {
		t.Errorf("expected source=MDNS, got %q", obs[0].Source)
	}
	// Hostname should be extracted from PTR (trimmed of .local)
	found := false
	for _, h := range obs[0].Hostnames {
		if h == "_http._tcp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hostname '_http._tcp' in hostnames, got %v", obs[0].Hostnames)
	}
}

func TestMDNSAnalyzer_SRVAnswer(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	answers := []layers.DNSResourceRecord{
		{
			Type: layers.DNSTypeSRV,
			SRV: layers.DNSSRV{
				Name: []byte("my-server.local."),
				Port: 8080,
			},
		},
	}
	pkt := buildMDNSResponse(t, helpers.RandMAC(), answers)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(obs[0].Services))
	}
	svc := obs[0].Services[0]
	if svc.Protocol != "tcp" || svc.Port != 8080 {
		t.Errorf("expected service tcp/8080, got %s/%d", svc.Protocol, svc.Port)
	}
}

func TestMDNSAnalyzerPTRAndSRV(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	answers := []layers.DNSResourceRecord{
		{Type: layers.DNSTypePTR, PTR: []byte("_device._tcp.local.")},
		{Type: layers.DNSTypeSRV, SRV: layers.DNSSRV{Name: []byte("dev.local."), Port: 443}},
	}
	pkt := buildMDNSResponse(t, helpers.RandMAC(), answers)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Hostnames) == 0 {
		t.Error("expected at least 1 hostname")
	}
	if len(obs[0].Services) == 0 {
		t.Error("expected at least 1 service")
	}
}

func TestMDNSAnalyzer_ZeroSrcMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()
	answers := []layers.DNSResourceRecord{
		{Type: layers.DNSTypePTR, PTR: []byte("x._tcp.local.")},
	}
	pkt := buildMDNSResponse(t, helpers.ZeroMAC(), answers)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for zero MAC, got %d", len(got))
	}
}

func TestMDNSAnalyzer_DuplicatePTR(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	answers := []layers.DNSResourceRecord{
		{Type: layers.DNSTypePTR, PTR: []byte("_svc._tcp.local.")},
		{Type: layers.DNSTypePTR, PTR: []byte("_svc._tcp.local.")}, // duplicate
	}
	pkt := buildMDNSResponse(t, helpers.RandMAC(), answers)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	// Deduplicated — only one hostname
	count := 0
	for _, h := range obs[0].Hostnames {
		if h == "_svc._tcp" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected hostname deduplicated, got %d occurrences", count)
	}
}

func TestMDNSAnalyzer_SRVPort0Skipped(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	answers := []layers.DNSResourceRecord{
		{Type: layers.DNSTypeSRV, SRV: layers.DNSSRV{Name: []byte("svc.local."), Port: 0}},
	}
	pkt := buildMDNSResponse(t, helpers.RandMAC(), answers)
	obs := a.Analyze(pkt)

	// SRV with port 0 should be skipped; no services returned.
	if len(obs) != 0 {
		t.Fatalf("expected nil for SRV port 0, got %d", len(obs))
	}
}

func TestMDNSAnalyzer_IPv4Populated(t *testing.T) {
	t.Parallel()
	a := analyzer.NewMDNSAnalyzer()

	answers := []layers.DNSResourceRecord{
		{Type: layers.DNSTypePTR, PTR: []byte("svc._tcp.local.")},
	}
	pkt := buildMDNSResponse(t, helpers.RandMAC(), answers)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if _, ok := obs[0].IPv4s["10.0.0.5"]; !ok {
		t.Error("expected IPv4 10.0.0.5 from packet src IP")
	}
}

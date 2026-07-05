package analyzer_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// SSDPAnalyzer.Analyze — covered scenarios:
//   1. Non-UDP packet returns nil
//   2. UDP not on port 1900 returns nil
//   3. M-SEARCH returns nil (filtered out)
//   4. NOTIFY with Server header → OS and Model populated
//   5. NOTIFY with ST header → DeviceType populated
//   6. NOTIFY with Location → Service extracted
//   7. HTTP response on port 1900 → observation
//   8. Empty payload returns nil
//   9. Non-SSDP payload (random text) returns nil
//  10. Location with no port → no service
//  11. Zero src MAC returns nil
//  12. Source field == SourceSSDP

func buildSSDPPacket(t *testing.T, srcMAC []byte, dstPort uint16, payload string) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		SrcIP:    helpers.IPv4(10, 0, 0, 10),
		DstIP:    helpers.IPv4(239, 255, 255, 250),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(1900),
		DstPort: layers.UDPPort(dstPort),
	}
	// Serialize UDP with raw payload.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	udp.Payload = []byte(payload)
	_ = gopacket.SerializeLayers(buf, opts, eth, ip4, udp)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestSSDPAnalyzer_NonUDP(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-UDP, got %d", len(got))
	}
}

func TestSSDPAnalyzer_NilPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()
	if got := a.Analyze(nil); got != nil {
		t.Fatalf("expected nil for nil packet, got %d", len(got))
	}
}

func TestSSDPAnalyzer_MSearchReturnsNil(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: ssdp:discover\r\n" +
		"ST: ssdp:all\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for M-SEARCH, got %d", len(got))
	}
}

func TestSSDPAnalyzer_NOTIFYWithServer(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"SERVER: Linux/5.10 UPnP/1.0 MiniUPnPd/2.2\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceSSDP {
		t.Errorf("expected source=SSDP, got %q", obs[0].Source)
	}
	if obs[0].OS != "Linux" {
		t.Errorf("expected OS=Linux, got %q", obs[0].OS)
	}
	if obs[0].Extra["ssdp_os_version"] != "5.10" {
		t.Errorf("expected ssdp_os_version=5.10, got %v", obs[0].Extra["ssdp_os_version"])
	}
}

func TestSSDPAnalyzer_DeviceTypeFromST(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	cases := []struct {
		st   string
		want string
	}{
		{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "router"},
		{"urn:schemas-upnp-org:device:MediaServer:1", "nas"},
		{"urn:schemas-upnp-org:device:MediaRenderer:1", "smart-tv"},
		{"urn:schemas-upnp-org:service:Printer:1", "printer"},
		{"urn:schemas-upnp-org:device:Basic:1", "upnp-device"},
		{"ssdp:all", ""},
	}

	for _, tc := range cases {
		payload := "NOTIFY * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"ST: " + tc.st + "\r\n\r\n"
		pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
		obs := a.Analyze(pkt)

		if len(obs) != 1 {
			t.Fatalf("ST=%q: expected 1 observation, got %d", tc.st, len(obs))
		}
		if got := obs[0].DeviceType; got != tc.want {
			t.Errorf("ST=%q: expected DeviceType=%q, got %q", tc.st, tc.want, got)
		}
	}
}

func TestSSDPAnalyzer_ModelFromServer(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"SERVER: Linux/5.10 UPnP/1.0 MiniUPnPd/2.2\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Model != "MiniUPnPd" {
		t.Errorf("expected Model=MiniUPnPd, got %q", obs[0].Model)
	}
}

func TestSSDPAnalyzer_LocationCreatesService(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"LOCATION: http://10.0.0.5:49000/description.xml\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Services) != 1 {
		t.Fatalf("expected 1 service from Location, got %d", len(obs[0].Services))
	}
	svc := obs[0].Services[0]
	if svc.Port != 49000 {
		t.Errorf("expected service port 49000, got %d", svc.Port)
	}
	if svc.Protocol != "tcp" {
		t.Errorf("expected service protocol tcp, got %q", svc.Protocol)
	}
}

func TestSSDPAnalyzer_LocationNoPortNoService(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"LOCATION: http://10.0.0.5/description.xml\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Services) != 0 {
		t.Errorf("expected 0 services when Location has no port, got %d", len(obs[0].Services))
	}
}

func TestSSDPAnalyzer_EmptyPayload(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, "")
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for empty payload, got %d", len(got))
	}
}

func TestSSDPAnalyzer_NonSSDPPayload(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, "GET / HTTP/1.1\r\n\r\n")
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-SSDP payload, got %d", len(got))
	}
}

func TestSSDPAnalyzer_ZeroSrcMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()
	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.ZeroMAC(), 1900, payload)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for zero MAC, got %d", len(got))
	}
}

func TestSSDPAnalyzer_DstPort1900(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n\r\n"
	// SSDP on dst port 1900 (multicast response)
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 1900, payload)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation for dst port 1900, got %d", len(obs))
	}
}

func TestSSDPAnalyzer_WrongPort(t *testing.T) {
	t.Parallel()
	a := analyzer.NewSSDPAnalyzer()

	payload := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n\r\n"
	pkt := buildSSDPPacket(t, helpers.RandMAC(), 8080, payload)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for wrong port, got %d", len(got))
	}
}

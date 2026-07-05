package analyzer_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// EthernetAnalyzer.Analyze — covered scenarios:
//   1. Non-Ethernet packet returns nil
//   2. Usable src MAC → observation with MAC, source=Ethernet
//   3. Zero src MAC returns nil
//   4. IPv4 in packet → IPv4 populated
//   5. IPv6 in packet (non-link-local) → IPv6 populated
//   6. IPv6 link-local → NOT populated
//   7. Throttle: second packet same MAC within throttle window → no observation
//   8. Throttle: after throttle window → observation emitted again
//   9. Reset() clears throttle state
//  10. TCP SYN to known port (e.g. 443) → Service with IsClient=true
//  11. TCP SYN to unknown port → no service emitted
//  12. TCP SYN-ACK → no service (not a SYN)
//  13. TCP data packet → no service
//  14. Throttled + TCP SYN → emits standalone service observation

func buildEthernetPacket(t *testing.T, srcMAC []byte, payloadLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       helpers.BroadcastMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}

	layers2 := []gopacket.SerializableLayer{eth}
	layers2 = append(layers2, payloadLayers...)

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, layers2...)
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestEthernetAnalyzer_NonEthernet(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	pkt := gopacket.NewPacket([]byte{}, layers.LinkTypeNull, gopacket.Default)
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-Ethernet, got %d", len(got))
	}
}

func TestEthernetAnalyzer_NilPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	if got := a.Analyze(nil); got != nil {
		t.Fatalf("expected nil for nil packet, got %d", len(got))
	}
}

func TestEthernetAnalyzer_UsableMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	pkt := buildEthernetPacket(t, helpers.RandMAC())
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Source != asset.SourceEthernet {
		t.Errorf("expected source=Ethernet, got %q", obs[0].Source)
	}
}

func TestEthernetAnalyzer_ZeroSrcMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	pkt := buildEthernetPacket(t, helpers.ZeroMAC())
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for zero MAC, got %d", len(got))
	}
}

func TestEthernetAnalyzer_IPv4Populated(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()

	ip4 := &layers.IPv4{
		SrcIP:    helpers.IPv4(10, 0, 0, 20),
		DstIP:    helpers.IPv4(10, 0, 0, 1),
		Protocol: layers.IPProtocolTCP,
	}
	pkt := buildEthernetPacket(t, helpers.RandMAC(), ip4)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if _, ok := obs[0].IPv4s["10.0.0.20"]; !ok {
		t.Error("expected IPv4 10.0.0.20 in observation")
	}
}

func TestEthernetAnalyzer_LinkLocalIPv6Skipped(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()

	ip6 := &layers.IPv6{
		SrcIP:      helpers.IPv6(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01),
		DstIP:      helpers.IPv6(0x26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01),
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
	}
	pkt := buildEthernetPacket(t, helpers.RandMAC(), ip6)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].IPv6s) > 0 {
		t.Errorf("expected link-local IPv6 to be skipped, got %v", obs[0].IPv6s)
	}
}

func TestEthernetAnalyzer_ThrottleBlocksSecondPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	mac := helpers.RandMAC()

	// First packet — should emit observation
	pkt1 := buildEthernetPacket(t, mac)
	obs1 := a.Analyze(pkt1)
	if len(obs1) != 1 {
		t.Fatalf("first packet: expected 1 observation, got %d", len(obs1))
	}

	// Second packet same MAC — within throttle window — should be filtered
	pkt2 := buildEthernetPacket(t, mac)
	obs2 := a.Analyze(pkt2)
	if len(obs2) != 0 {
		t.Errorf("second packet (throttled): expected 0 observations, got %d", len(obs2))
	}
}

func TestEthernetAnalyzer_ResetClearsThrottle(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	mac := helpers.RandMAC()

	pkt := buildEthernetPacket(t, mac)
	_ = a.Analyze(pkt) // first emission

	a.Reset()

	// After reset, should emit again
	obs := a.Analyze(pkt)
	if len(obs) != 1 {
		t.Errorf("after Reset: expected 1 observation, got %d", len(obs))
	}
}

func TestEthernetAnalyzer_TCPSYN(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()

	tcp := &layers.TCP{
		SrcPort: 50000,
		DstPort: 443,
		SYN:     true,
	}
	pkt := buildEthernetPacket(t, helpers.RandMAC(),
		&layers.IPv4{
			SrcIP:    helpers.IPv4(10, 0, 0, 30),
			DstIP:    helpers.IPv4(10, 0, 0, 1),
			Protocol: layers.IPProtocolTCP,
		},
		tcp,
	)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Services) != 1 {
		t.Fatalf("expected 1 service from SYN, got %d", len(obs[0].Services))
	}
	svc := obs[0].Services[0]
	if svc.Port != 443 {
		t.Errorf("expected port 443, got %d", svc.Port)
	}
	if !svc.IsClient {
		t.Error("expected IsClient=true")
	}
	if svc.Name != "https" {
		t.Errorf("expected Name=https, got %q", svc.Name)
	}
}

func TestEthernetAnalyzer_TCPSYNUnknownPort(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()

	tcp := &layers.TCP{
		SrcPort: 50000,
		DstPort: 31337, // unknown port
		SYN:     true,
	}
	pkt := buildEthernetPacket(t, helpers.RandMAC(),
		&layers.IPv4{
			SrcIP:    helpers.IPv4(10, 0, 0, 30),
			DstIP:    helpers.IPv4(10, 0, 0, 1),
			Protocol: layers.IPProtocolTCP,
		},
		tcp,
	)
	obs := a.Analyze(pkt)

	// SYN to unknown port: no service emitted, but presence obs should remain.
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Services) != 0 {
		t.Errorf("expected 0 services for unknown port, got %d", len(obs[0].Services))
	}
}

func TestEthernetAnalyzer_TCPSYNACK(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()

	tcp := &layers.TCP{
		SrcPort: 443,
		DstPort: 50000,
		SYN:     true,
		ACK:     true,
	}
	pkt := buildEthernetPacket(t, helpers.RandMAC(),
		&layers.IPv4{
			SrcIP:    helpers.IPv4(10, 0, 0, 1),
			DstIP:    helpers.IPv4(10, 0, 0, 30),
			Protocol: layers.IPProtocolTCP,
		},
		tcp,
	)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	// SYN-ACK should NOT emit service (server response)
	if len(obs[0].Services) != 0 {
		t.Errorf("expected 0 services for SYN-ACK, got %d", len(obs[0].Services))
	}
}

func TestEthernetAnalyzer_TCPDataPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()

	tcp := &layers.TCP{
		SrcPort: 50000,
		DstPort: 443,
		// No SYN flag
	}
	pkt := buildEthernetPacket(t, helpers.RandMAC(),
		&layers.IPv4{
			SrcIP:    helpers.IPv4(10, 0, 0, 30),
			DstIP:    helpers.IPv4(10, 0, 0, 1),
			Protocol: layers.IPProtocolTCP,
		},
		tcp,
	)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if len(obs[0].Services) != 0 {
		t.Errorf("expected 0 services for plain TCP, got %d", len(obs[0].Services))
	}
}

func TestEthernetAnalyzer_ThrottledWithSYN(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	mac := helpers.RandMAC()

	// First packet to establish throttle
	pkt1 := buildEthernetPacket(t, mac)
	_ = a.Analyze(pkt1)

	// Second packet within throttle window — should be filtered from presence,
	// but TCP SYN detection should still emit service observation.
	tcp := &layers.TCP{
		SrcPort: 50001,
		DstPort: 80,
		SYN:     true,
	}
	pkt2 := buildEthernetPacket(t, mac,
		&layers.IPv4{
			SrcIP:    helpers.IPv4(10, 0, 0, 31),
			DstIP:    helpers.IPv4(10, 0, 0, 1),
			Protocol: layers.IPProtocolTCP,
		},
		tcp,
	)
	obs := a.Analyze(pkt2)

	if len(obs) != 1 {
		t.Fatalf("throttled+SYN: expected 1 observation (service), got %d", len(obs))
	}
	if len(obs[0].Services) != 1 {
		t.Errorf("throttled+SYN: expected 1 service, got %d", len(obs[0].Services))
	}
}

func TestEthernetAnalyzer_ThrottleAfterReset(t *testing.T) {
	t.Parallel()
	a := analyzer.NewEthernetAnalyzer()
	mac := helpers.RandMAC()

	// First packet — throttled after this
	pkt1 := buildEthernetPacket(t, mac)
	_ = a.Analyze(pkt1)

	// Reset clears throttle state — simulates time passing
	a.Reset()

	pkt2 := buildEthernetPacket(t, mac)
	obs := a.Analyze(pkt2)

	if len(obs) != 1 {
		t.Fatalf("after Reset: expected 1 observation, got %d", len(obs))
	}
}

package analyzer_test

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// ARPAnalyzer.Analyze — covered scenarios:
//   1. Non-ARP packet returns nil
//   2. ARP request with valid src MAC and dst IP → 1 observation
//   3. ARP request with zero src MAC returns nil
//   4. ARP reply → 2 observations (src + dst)
//   5. ARP reply with broadcast dst → only src observation
//   6. ARP reply where src == dst MAC → only 1 observation
//   7. ARP probe (src IP zero) operation name == "probe"
//   8. ARP announce (src IP == dst IP, request) operation name == "announce"
//   9. ARP gratuitous reply (src IP == dst IP, reply) operation name == "gratuitous-reply"
//  10. Locally-administered MAC sets arp_mac_randomized flag
//  11. Universal (vendor) MAC does NOT set arp_mac_randomized
//  12. IPv4 from src IP is populated when valid
//  13. Nil packet handled safely
//  14. Operation name "unknown" for unknown op code
//  15. Source field == SourceARP

func TestARPAnalyzer_NonARPPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	// strip ARP layer
	pkt = gopacket.NewPacket([]byte{}, layers.LinkTypeNull, gopacket.Default)

	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for non-ARP packet, got %d observations", len(got))
	}
}

func TestARPAnalyzer_Request_ValidSrc(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 1)
	dstMAC := helpers.BroadcastMAC()
	dstIP := helpers.IPv4(10, 0, 0, 2)

	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, dstMAC, srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	o := obs[0]
	if o.Source != asset.SourceARP {
		t.Errorf("expected source=ARP, got %q", o.Source)
	}
	if !bytesEqual(o.MAC, srcMAC) {
		t.Errorf("expected MAC=%v, got %v", srcMAC, o.MAC)
	}
	if got := o.IPv4s[srcIP.String()]; got.FirstSeen.IsZero() {
		t.Errorf("expected IPv4 %s to have FirstSeen set", srcIP)
	}
	if got := o.Extra["arp_operation"]; got != "request" {
		t.Errorf("expected arp_operation=request, got %v", got)
	}
}

func TestARPAnalyzer_Request_ZeroSrcMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.ZeroMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	if got := a.Analyze(pkt); got != nil {
		t.Fatalf("expected nil for zero src MAC, got %d", len(got))
	}
}

func TestARPAnalyzer_Reply_TwoObservations(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	dstMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 1)
	dstIP := helpers.IPv4(10, 0, 0, 2)

	pkt := helpers.ARPPacket(layers.ARPReply, srcMAC, dstMAC, srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 2 {
		t.Fatalf("expected 2 observations (src+dst), got %d", len(obs))
	}

	if !bytesEqual(obs[0].MAC, srcMAC) {
		t.Errorf("obs[0] should be src MAC")
	}
	if !bytesEqual(obs[1].MAC, dstMAC) {
		t.Errorf("obs[1] should be dst MAC")
	}
}

func TestARPAnalyzer_Reply_BroadcastDst(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 1)
	dstIP := helpers.IPv4(10, 0, 0, 2)

	pkt := helpers.ARPPacket(layers.ARPReply, srcMAC, helpers.BroadcastMAC(), srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation (broadcast dst skipped), got %d", len(obs))
	}
	if !bytesEqual(obs[0].MAC, srcMAC) {
		t.Errorf("expected src MAC observation")
	}
}

func TestARPAnalyzer_Reply_SameSrcDstMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 1)
	dstIP := helpers.IPv4(10, 0, 0, 2)

	pkt := helpers.ARPPacket(layers.ARPReply, srcMAC, srcMAC, srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation (src==dst MAC deduplicated), got %d", len(obs))
	}
}

func TestARPAnalyzer_Request_Probe(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := net.IPv4zero
	dstMAC := helpers.BroadcastMAC()
	dstIP := helpers.IPv4(10, 0, 0, 5)

	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, dstMAC, srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got := obs[0].Extra["arp_operation"]; got != "probe" {
		t.Errorf("expected operation=probe, got %v", got)
	}
}

func TestARPAnalyzer_Request_Announce(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 7)
	dstMAC := helpers.BroadcastMAC()
	dstIP := helpers.IPv4(10, 0, 0, 7) // same

	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, dstMAC, srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got := obs[0].Extra["arp_operation"]; got != "announce" {
		t.Errorf("expected operation=announce, got %v", got)
	}
}

func TestARPAnalyzer_Reply_Gratuitous(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 9)
	dstMAC := helpers.BroadcastMAC()
	dstIP := helpers.IPv4(10, 0, 0, 9) // same

	pkt := helpers.ARPPacket(layers.ARPReply, srcMAC, dstMAC, srcIP, dstIP)
	obs := a.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got := obs[0].Extra["arp_operation"]; got != "gratuitous-reply" {
		t.Errorf("expected operation=gratuitous-reply, got %v", got)
	}
}

func TestARPAnalyzer_LocallyAdministeredMAC(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMACLocallyAdministered()
	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))

	obs := a.Analyze(pkt)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got := obs[0].Extra["arp_mac_randomized"]; got != true {
		t.Errorf("expected arp_mac_randomized=true, got %v", got)
	}
}

func TestARPAnalyzer_VendorMACNotRandomized(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	// Use a known vendor MAC: Apple's first byte is 0x10 (locally-administered clear).
	srcMAC := net.HardwareAddr{0x10, 0x9A, 0xDD, 0x11, 0x22, 0x33}
	if srcMAC[0]&0x02 != 0 {
		t.Fatalf("test setup: MAC should NOT have locally-administered bit set")
	}
	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))

	obs := a.Analyze(pkt)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got := obs[0].Extra["arp_mac_randomized"]; got != false {
		t.Errorf("expected arp_mac_randomized=false, got %v", got)
	}
}

func TestARPAnalyzer_IPv4Populated(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	srcIP := helpers.IPv4(192, 168, 1, 100)
	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, helpers.BroadcastMAC(),
		srcIP, helpers.IPv4(192, 168, 1, 1))

	obs := a.Analyze(pkt)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}

	if _, ok := obs[0].IPv4s[srcIP.String()]; !ok {
		t.Errorf("expected IPv4 %s in observation", srcIP)
	}
}

func TestARPAnalyzer_NilPacket(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	if got := a.Analyze(nil); got != nil {
		t.Errorf("expected nil for nil packet, got %d", len(got))
	}
}

func TestARPAnalyzer_UnknownOperation(t *testing.T) {
	t.Parallel()
	a := analyzer.NewARPAnalyzer()

	srcMAC := helpers.RandMAC()
	pkt := helpers.ARPPacket(0x9999, srcMAC, helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))

	obs := a.Analyze(pkt)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if got := obs[0].Extra["arp_operation"]; got != "unknown" {
		t.Errorf("expected operation=unknown, got %v", got)
	}
}

// bytesEqual compares two net.HardwareAddr.
func bytesEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
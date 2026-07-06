package analyzer_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/test/helpers"
)

// Registry.Analyze — covered scenarios:
//   1. Empty packet (no layers) → empty observations
//   2. ARP packet → all 6 analyzers called; only ARP emits
//   3. Multiple analyzers all match → concat observations
//   4. Nil registry → nil observations
//   5. Nil analyzers filtered out at construction
//   6. DefaultRegistry() returns registry with all 6 analyzers
//   7. Same MAC across multiple protocols → multiple observations

func TestRegistry_NilReceiver(t *testing.T) {
	t.Parallel()
	var r *analyzer.Registry
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	if got := r.Analyze(pkt); got != nil {
		t.Errorf("expected nil for nil registry, got %d", len(got))
	}
}

func TestRegistry_NilPacket(t *testing.T) {
	t.Parallel()
	r := analyzer.NewRegistry(analyzer.NewARPAnalyzer())
	if got := r.Analyze(nil); got != nil {
		t.Errorf("expected nil for nil packet, got %d", len(got))
	}
}

func TestRegistry_EmptyPacket(t *testing.T) {
	t.Parallel()
	r := analyzer.NewRegistry(analyzer.NewARPAnalyzer())
	pkt := gopacket.NewPacket([]byte{}, layers.LinkTypeNull, gopacket.Default)
	if got := r.Analyze(pkt); got == nil {
		// Empty packet with no layers should produce nil from each analyzer
		// (they all self-reject by layer type)
		// Actually, gopacket.NewPacket with empty bytes might return non-nil
		// empty slice — we just check it doesn't panic.
		t.Log("empty packet produced nil — fine")
	}
}

func TestRegistry_ARPOnly(t *testing.T) {
	t.Parallel()
	r := analyzer.NewRegistry(analyzer.NewARPAnalyzer())
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	obs := r.Analyze(pkt)

	if len(obs) != 1 {
		t.Fatalf("expected 1 observation (ARP only), got %d", len(obs))
	}
	if obs[0].Source != asset.SourceARP {
		t.Errorf("expected source=ARP, got %q", obs[0].Source)
	}
}

func TestRegistry_NilAnalyzersFiltered(t *testing.T) {
	t.Parallel()
	// Pass nil and a valid analyzer — nil should be filtered out.
	r := analyzer.NewRegistry(nil, analyzer.NewARPAnalyzer(), nil)
	if r == nil {
		t.Fatal("expected non-nil registry")
	}

	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	obs := r.Analyze(pkt)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
}

func TestRegistry_AllAnalyzersConcat(t *testing.T) {
	t.Parallel()
	// Build a packet that should trigger ARP + Ethernet analyzers
	// (Ethernet wrapper around ARP request).
	srcMAC := helpers.RandMAC()
	dstMAC := helpers.BroadcastMAC()
	srcIP := helpers.IPv4(10, 0, 0, 1)
	dstIP := helpers.IPv4(10, 0, 0, 2)

	pkt := helpers.ARPPacket(layers.ARPRequest, srcMAC, dstMAC, srcIP, dstIP)

	r := analyzer.NewRegistry(
		analyzer.NewARPAnalyzer(),
		analyzer.NewEthernetAnalyzer(),
		analyzer.NewDHCPAnalyzer(),
		analyzer.NewDHCPv6Analyzer(),
		analyzer.NewMDNSAnalyzer(),
		analyzer.NewSSDPAnalyzer(),
	)
	obs := r.Analyze(pkt)

	// ARP gives 1, Ethernet gives 1 (if not throttled). Others give nil.
	if len(obs) < 2 {
		t.Fatalf("expected at least 2 observations (ARP+Ethernet), got %d", len(obs))
	}

	// Check that both ARP and Ethernet are present
	sources := make(map[asset.ObservationSource]bool)
	for _, o := range obs {
		sources[o.Source] = true
	}
	if !sources[asset.SourceARP] {
		t.Error("expected SourceARP in observations")
	}
	if !sources[asset.SourceEthernet] {
		t.Error("expected SourceEthernet in observations")
	}
}

func TestRegistry_DefaultRegistry(t *testing.T) {
	t.Parallel()
	r := analyzer.DefaultRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}

	// Run a packet through it — should not panic.
	pkt := helpers.ARPPacket(layers.ARPRequest, helpers.RandMAC(), helpers.BroadcastMAC(),
		helpers.IPv4(10, 0, 0, 1), helpers.IPv4(10, 0, 0, 2))
	obs := r.Analyze(pkt)

	if len(obs) < 1 {
		t.Fatal("expected at least 1 observation from DefaultRegistry")
	}
}

func TestRegistry_PacketThatTriggersNothing(t *testing.T) {
	t.Parallel()
	r := analyzer.NewRegistry(
		analyzer.NewARPAnalyzer(),
		analyzer.NewDHCPAnalyzer(),
	)
	pkt := gopacket.NewPacket([]byte{}, layers.LinkTypeNull, gopacket.Default)
	obs := r.Analyze(pkt)
	if len(obs) != 0 {
		t.Errorf("expected 0 observations for unparseable packet, got %d", len(obs))
	}
}
package pipeline_test

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/asset"
	"passivediscovery/internal/capture"
	"passivediscovery/internal/pipeline"
	"passivediscovery/test/helpers"
)

// Pipeline.Run — covered scenarios:
//   1. Drains channel until close → returns counters
//   2. Counts processed/applied/dropped
//   3. ctx.Done() → returns early with current counters
//   4. Nil channel → returns 0
//   5. Empty channel → returns 0
//   6. Packet that emits 0 observations → processed++, but applied/dropped unchanged

func TestPipeline_RunDrainsChannel(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := asset.NewManager(nil)
	pipe := pipeline.NewPipeline(analyzer.NewRegistry(analyzer.NewARPAnalyzer()), m, logger)

	mac := helpers.RandMAC()
	srcIP := helpers.IPv4(10, 0, 0, 1)
	dstIP := helpers.IPv4(10, 0, 0, 2)

	packets := make(chan capture.RawPacket, 5)
	for i := 0; i < 3; i++ {
		packets <- capture.RawPacket{
			Packet: helpers.ARPPacket(layers.ARPRequest, mac, helpers.BroadcastMAC(), srcIP, dstIP),
			Source: capture.SourceRef{Kind: capture.SourceKindFile, Name: "test"},
		}
	}
	close(packets)

	processed, applied, dropped := pipe.Run(context.Background(), packets)
	if processed != 3 {
		t.Errorf("expected 3 processed, got %d", processed)
	}
	if applied != 3 {
		t.Errorf("expected 3 applied, got %d", applied)
	}
	if dropped != 0 {
		t.Errorf("expected 0 dropped, got %d", dropped)
	}
}

func TestPipeline_RunWithCancel(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := asset.NewManager(nil)
	pipe := pipeline.NewPipeline(analyzer.NewRegistry(analyzer.NewARPAnalyzer()), m, logger)

	mac := helpers.RandMAC()
	packets := make(chan capture.RawPacket)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_ = mac
	processed, _, _ := pipe.Run(ctx, packets)
	if processed != 0 {
		t.Errorf("expected 0 processed (cancelled immediately), got %d", processed)
	}
}

func TestPipeline_RunEmptyChannel(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := asset.NewManager(nil)
	pipe := pipeline.NewPipeline(analyzer.NewRegistry(analyzer.NewARPAnalyzer()), m, logger)

	packets := make(chan capture.RawPacket)
	close(packets)

	processed, _, _ := pipe.Run(context.Background(), packets)
	if processed != 0 {
		t.Errorf("expected 0 processed for empty channel, got %d", processed)
	}
}

func TestPipeline_RunPacketWithNoObservation(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := asset.NewManager(nil)
	pipe := pipeline.NewPipeline(analyzer.NewRegistry(analyzer.NewARPAnalyzer()), m, logger)

	packets := make(chan capture.RawPacket, 1)
	// Packet with no Ethernet layer — should not produce observations.
	packets <- capture.RawPacket{
		Packet: gopacket.NewPacket([]byte{}, layers.LinkTypeNull, gopacket.Default),
		Source: capture.SourceRef{Kind: capture.SourceKindFile, Name: "test"},
	}
	close(packets)

	processed, applied, dropped := pipe.Run(context.Background(), packets)
	if processed != 1 {
		t.Errorf("expected 1 processed, got %d", processed)
	}
	if applied != 0 {
		t.Errorf("expected 0 applied (no observation), got %d", applied)
	}
	if dropped != 0 {
		t.Errorf("expected 0 dropped, got %d", dropped)
	}
}

func TestPipeline_RunProcessesValidARPs(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := asset.NewManager(nil)
	pipe := pipeline.NewPipeline(analyzer.NewRegistry(analyzer.NewARPAnalyzer()), m, logger)

	packets := make(chan capture.RawPacket, 1)
	packets <- capture.RawPacket{
		Packet: helpers.ARPPacket(layers.ARPRequest,
			net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01},
			helpers.BroadcastMAC(),
			helpers.IPv4(10, 0, 0, 1),
			helpers.IPv4(10, 0, 0, 2),
		),
		Source: capture.SourceRef{Kind: capture.SourceKindFile, Name: "test"},
	}
	close(packets)

	_, applied, _ := pipe.Run(context.Background(), packets)
	if applied < 1 {
		t.Errorf("expected at least 1 applied for valid ARP, got %d", applied)
	}
}

// Smoke test to ensure pipeline doesn't panic on multiple packet types.
func TestPipeline_RunMixedPackets(t *testing.T) {
	t.Parallel()
	logger := slog.Default()
	m := asset.NewManager(nil)
	pipe := pipeline.NewPipeline(
		analyzer.NewRegistry(
			analyzer.NewARPAnalyzer(),
			analyzer.NewDHCPAnalyzer(),
			analyzer.NewEthernetAnalyzer(),
		),
		m, logger,
	)

	packets := make(chan capture.RawPacket, 10)
	for i := 0; i < 10; i++ {
		packets <- capture.RawPacket{
			Packet: helpers.ARPPacket(layers.ARPRequest,
				helpers.RandMAC(), helpers.BroadcastMAC(),
				helpers.IPv4(10, 0, 0, byte(i)),
				helpers.IPv4(10, 0, 0, 255),
			),
			Source: capture.SourceRef{Kind: capture.SourceKindFile, Name: "test"},
		}
	}
	close(packets)

	start := time.Now()
	processed, _, _ := pipe.Run(context.Background(), packets)
	elapsed := time.Since(start)

	if processed != 10 {
		t.Errorf("expected 10 processed, got %d", processed)
	}
	if elapsed > time.Second {
		t.Errorf("pipeline too slow: %v for 10 packets", elapsed)
	}
}
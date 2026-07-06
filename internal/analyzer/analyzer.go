package analyzer

import (
	"github.com/google/gopacket"

	"passivediscovery/internal/asset"
)

type Analyzer interface {
	Analyze(packet gopacket.Packet) []asset.Observation
	AnalyzeCtx(ctx *PacketCtx) []asset.Observation
}
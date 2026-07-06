package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

type Registry struct { // Analyzer Registry
	analyzers []Analyzer
}

func NewRegistry(analyzers ...Analyzer) *Registry {
	copied := make([]Analyzer, 0, len(analyzers))
	for _, a := range analyzers {
		if a != nil {
			copied = append(copied, a)
		}
	}
	return &Registry{analyzers: copied}
}

func DefaultRegistry() *Registry {
	return NewRegistry(
		NewEthernetAnalyzer(),
		NewARPAnalyzer(),
		NewDHCPAnalyzer(),
		NewMDNSAnalyzer(),
		NewSSDPAnalyzer(),
		NewDHCPv6Analyzer(),
	)
}

func (r *Registry) AnalyzeCtx(ctx *PacketCtx) []asset.Observation {
	if r == nil || ctx == nil {
		return nil
	}

	var observations []asset.Observation

	for _, a := range r.analyzers {
		observations = append(observations, a.AnalyzeCtx(ctx)...)
	}
	return observations
}

func (r *Registry) Analyze(packet gopacket.Packet) []asset.Observation {
	if r == nil {
		return nil
	}
	ctx := DecodePacketCtx(packet)
	return r.AnalyzeCtx(&ctx)
}

var _ = layers.LayerTypeEthernet 
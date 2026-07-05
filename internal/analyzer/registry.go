package analyzer

import (
	"github.com/google/gopacket"

	"passivediscovery/internal/asset"
)

type Registry struct { // Analyzer Registry
	analyzers []Analyzer
}

func NewRegistry(analyzers ...Analyzer) *Registry {
	copied := make([]Analyzer, 0, len(analyzers))
	for _, analyzer := range analyzers {
		if analyzer != nil {
			copied = append(copied, analyzer)
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

func (r *Registry) Analyze(packet gopacket.Packet) []asset.Observation {
	if r == nil {
		return nil
	}

	observations := make([]asset.Observation, 0, len(r.analyzers)) // default
	for _, analyzer := range r.analyzers {
		observations = append(observations, analyzer.Analyze(packet)...) // unpacking operator
	}
	return observations
}

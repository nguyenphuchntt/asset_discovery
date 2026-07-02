package analyzer

import (
	"passivediscovery/internal/asset"
	"passivediscovery/internal/decode"
)

type Registry struct {
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

func DefaultMinimalRegistry() *Registry {
	return NewRegistry(
		NewARPAnalyzer(),
		NewDHCPAnalyzer(),
	)
}

func (r *Registry) Analyze(packet decode.DecodedPacket) []asset.Observation {
	if r == nil {
		return nil
	}

	observations := make([]asset.Observation, 0, len(r.analyzers))
	for _, analyzer := range r.analyzers {
		observations = append(observations, analyzer.Analyze(packet)...)
	}
	return observations
}

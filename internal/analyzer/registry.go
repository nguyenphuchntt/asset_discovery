package analyzer

import (
	"github.com/google/gopacket"

	"passivediscovery/internal/asset"
)

// Registry runs a fixed set of Analyzers against every packet it is given.
//
// The set is built once at construction time (typically via DefaultRegistry)
// and never mutated afterwards — registries are safe for concurrent use as
// long as the analyzers themselves are.
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

// DefaultRegistry returns the production analyzer set: passive ARP + DHCPv4
// observations. Add new protocols here as they land.
func DefaultRegistry() *Registry {
	return NewRegistry(
		NewARPAnalyzer(),
		NewDHCPAnalyzer(),
	)
}

// Analyze fans the packet out to every registered analyzer and concatenates
// their observations. The order matches registration order; callers must
// not rely on a specific ordering.
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

// analyzer.go defines the analyzer contract.
//
// An analyzer converts decoded packet evidence into zero or more asset
// observations. It should not mutate asset state, persist data, or decide final
// identity merges. Multiple analyzers may inspect the same decoded packet.
package analyzer

import (
	"passivediscovery/internal/asset"
	"passivediscovery/internal/decode"
)

type Analyzer interface {
	Analyze(packet decode.DecodedPacket) []asset.Observation
}

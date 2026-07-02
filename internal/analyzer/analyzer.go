package analyzer

import (
	"passivediscovery/internal/asset"
	"passivediscovery/internal/decode"
)

type Analyzer interface {
	Analyze(packet decode.DecodedPacket) []asset.Observation
}

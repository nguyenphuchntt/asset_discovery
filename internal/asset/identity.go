package asset

import "strings"

// IdentifierType tags the kind of value carried by an Identifier.
type IdentifierType string

const (
	IdentifierMAC      IdentifierType = "mac"
	IdentifierIPv4     IdentifierType = "ipv4"
	IdentifierIPv6     IdentifierType = "ipv6"
	IdentifierHostname IdentifierType = "hostname"
)

// Identifier is one keyable piece of evidence about an asset: a MAC address,
// an IP address, or a hostname. Identifiers drive asset resolution — two
// observations sharing any identifier resolve to the same asset.
type Identifier struct {
	Type  IdentifierType
	Value string
}

// Key returns the index key for this identifier. Keys are case-folded so
// "AA:BB:..." and "aa:bb:..." resolve identically.
func (i Identifier) Key() string {
	return strings.ToLower(string(i.Type) + ":" + i.Value)
}

// primary returns the most stable identifier from a list. Stability order:
// MAC > IPv4 > IPv6 > hostname (MAC is wired to hardware, IP can change).
func primary(ids []Identifier) (Identifier, bool) {
	for _, want := range []IdentifierType{
		IdentifierMAC, IdentifierIPv4, IdentifierIPv6, IdentifierHostname,
	} {
		for _, id := range ids {
			if id.Type == want && id.Value != "" {
				return id, true
			}
		}
	}
	return Identifier{}, false
}

// uniqueKeys returns the deduplicated, non-empty keys for a list of identifiers.
func uniqueKeys(ids []Identifier) []string {
	keys := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id.Value == "" {
			continue
		}
		k := id.Key()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	return keys
}

// GenerateAssetID returns a stable ID derived from the primary identifier.
// Two observations that share a primary identifier (e.g. the same MAC) will
// always produce the same AssetID — this is what lets the resolver merge
// previously-seen-tap-separately evidence into one asset.
//
// Returns "" if the identifiers carry no usable value (which Apply treats as
// "skip this observation").
func GenerateAssetID(ids []Identifier) AssetID {
	p, ok := primary(ids)
	if !ok {
		return ""
	}
	return AssetID(p.Key())
}
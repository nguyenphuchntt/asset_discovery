package asset

import "strings"

type IdentifierType string

const (
	IdentifierMAC IdentifierType = "mac"
	IdentifierIPv4 IdentifierType = "ipv4"
	IdentifierIPv6 IdentifierType = "ipv6"
	IdentifierHostname IdentifierType = "hostname"
)

type Identifier struct {
	Type IdentifierType
	Value string
}

type IdentitySet struct {
	Identifiers []Identifier
}

var identifierPriority = []IdentifierType{
	IdentifierMAC,
	IdentifierIPv4,
	IdentifierIPv6,
	IdentifierHostname,
}

func (i Identifier) Key() string { // e.g <mac>:<macAddr>
	return strings.ToLower(string(i.Type) + ":" + i.Value)
}

func (s IdentitySet) Keys() []string { // array of all keys without duplicate
	keys := make([]string, 0, len(s.Identifiers))
	seen := make(map[string]struct{}, len(s.Identifiers)) // set
	for _, identifier := range s.Identifiers {
		if identifier.Value == "" {
			continue
		}
		key := identifier.Key()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func (s IdentitySet) Primary() (Identifier, bool) { // return most reliable key
	for _, wantType := range identifierPriority { // desc
		for _, identifier := range s.Identifiers {
			if identifier.Type == wantType && identifier.Value != "" {
				return identifier, true
			}
		}
	}
	return Identifier{}, false
}

func GenerateAssetID(subject IdentitySet) AssetID {
	primary, ok := subject.Primary()
	if !ok {
		return ""
	}
	return AssetID(primary.Key())
}

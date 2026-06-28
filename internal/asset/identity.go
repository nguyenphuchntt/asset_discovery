// identity.go defines identity primitives used to resolve observations into
// stable assets.
//
// Identifiers are evidence keys, not final asset IDs. AssetManager/Resolver
// decides how strong each key is and whether multiple identifiers belong to the
// same internal asset.
package asset

type IdentifierType string

const (
	IdentifierMAC      IdentifierType = "mac"
	IdentifierIPv4     IdentifierType = "ipv4"
	IdentifierIPv6     IdentifierType = "ipv6"
	IdentifierDUID     IdentifierType = "duid"
	IdentifierHostname IdentifierType = "hostname"
	IdentifierFQDN     IdentifierType = "fqdn"
	IdentifierService  IdentifierType = "service"
)

type Identifier struct {
	Type  IdentifierType
	Value string
}

type IdentitySet struct {
	Identifiers []Identifier
}

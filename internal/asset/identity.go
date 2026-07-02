package asset

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

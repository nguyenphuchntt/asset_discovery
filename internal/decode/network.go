// network.go will decode network-layer metadata.
//
// It should extract IPv4/IPv6 addresses, protocol numbers, TTL/hop limit if
// useful for fingerprinting, and ICMP/NDP hooks for later analyzers.
package decode

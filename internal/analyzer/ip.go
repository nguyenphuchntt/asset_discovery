// ip.go will create observations from IPv4/IPv6 packet metadata.
//
// It should correlate source/destination IPs with link-layer MACs when the
// capture position makes that trustworthy, and feed protocol/byte counters to
// stats without over-claiming identity.
package analyzer

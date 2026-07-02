// lookup.go will define the VendorLookup interface and in-memory lookup.
//
// Responsibilities:
// - normalize MAC prefixes;
// - support IEEE OUI/Wireshark manuf style data;
// - return empty vendor for unknown prefixes;
// - keep lookup cheap enough for packet-path enrichment.
package oui

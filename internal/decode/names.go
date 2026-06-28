// names.go will decode local name-service protocols when supported.
//
// Candidate protocols for the current scope are mDNS, LLMNR, and NBNS because
// they are common LAN discovery/name broadcasts or multicasts. Resolver traffic
// outside this local-discovery scope should not create external-domain assets.
package decode

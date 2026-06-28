// ethernet.go will decode link-layer metadata.
//
// It should extract source/destination MAC, EtherType, VLAN tags if present,
// frame length, and flags needed by analyzers to reject broadcast/multicast or
// zero addresses.
package decode

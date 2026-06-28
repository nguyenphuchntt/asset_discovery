// decoder_test.go will contain decoder unit tests.
//
// Planned cases:
// - ARP request/reply/gratuitous packets;
// - DHCPv4 DORA packets and malformed options;
// - mixed traffic packets that should still expose Ethernet/IP activity;
// - malformed packets never panic.
package decode

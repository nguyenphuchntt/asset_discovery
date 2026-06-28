// ethernet.go will create low-confidence activity observations from Ethernet
// frames.
//
// It can update last-seen for source MAC addresses even when higher-level
// protocols are not parsed. It should avoid creating assets from broadcast,
// multicast, zero, or locally meaningless addresses without clear policy.
package analyzer

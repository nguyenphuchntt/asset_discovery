// bpf.go will own BPF filter validation and application.
//
// BPF is an operational tradeoff: narrow filters reduce load but may hide
// packets needed for lifecycle accuracy. The code should support minimal
// ARP/DHCP demo filters and broader full-observation modes.
package capture

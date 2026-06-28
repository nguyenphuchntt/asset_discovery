// live.go will implement live passive capture from a network interface.
//
// Responsibilities:
// - open pcap.OpenLive in read-only capture mode;
// - apply configured BPF;
// - expose received/dropped stats;
// - return clear errors for missing permissions or invalid interfaces;
// - never send packets or trigger active discovery.
package capture

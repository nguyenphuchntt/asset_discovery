// validation.go will hold cross-field configuration checks.
//
// Examples:
// - exactly one of --pcap or --iface unless a mode explicitly allows both;
// - live mode requires an interface;
// - durations must be positive;
// - output/API/storage settings must be compatible with selected mode.
package config

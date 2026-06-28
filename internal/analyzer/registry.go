// registry.go will manage the enabled analyzer set.
//
// The registry should run all analyzers that can extract evidence from a
// DecodedPacket. Adding a new protocol analyzer should not require changing
// cmd/discovery or pipeline control flow.
package analyzer

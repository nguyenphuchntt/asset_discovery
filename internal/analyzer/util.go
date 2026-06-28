// util.go contains analyzer-local helpers.
//
// Helpers here should stay small and protocol-focused, such as MAC usability
// checks and human-readable operation names. Shared domain normalization should
// live in internal/asset instead.
package analyzer

import "net"

func isUsableMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

func arpOperationName(operation uint16) (string, error) {
	switch operation {
	case 1:
		return "request", nil
	case 2:
		return "reply", nil
	default:
		return "unknown", nil
	}
}

func appendIfNotEmpty(values []string, value string) []string {
	if value == "" {
		return values
	}
	return append(values, value)
}

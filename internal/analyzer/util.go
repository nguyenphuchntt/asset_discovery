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

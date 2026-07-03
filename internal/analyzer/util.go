package analyzer

// isUsableMAC returns true for a 6-byte MAC that is not the all-zero sentinel
// (which the wire occasionally uses as "no hardware address known").
// Takes []byte so it works directly with gopacket's ARP/DHCP layer fields
// without conversion at the call site.
func isUsableMAC(mac []byte) bool {
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

func arpOperationName(operation uint16) string {
	switch operation {
	case 1:
		return "request"
	case 2:
		return "reply"
	default:
		return "unknown"
	}
}

func dhcpMessageTypeName(messageType uint16) string {
	switch messageType {
	case 1:
		return "discover"
	case 2:
		return "offer"
	case 3:
		return "request"
	case 4:
		return "decline"
	case 5:
		return "ack"
	case 6:
		return "nak"
	case 7:
		return "release"
	case 8:
		return "inform"
	default:
		return "unknown"
	}
}
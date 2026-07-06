package analyzer

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

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

func isBroadcastMAC(mac []byte) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}

func isLocallyAdministeredMAC(mac []byte) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&0x02 != 0 // first bit 
}

func arpOperationName(arp *layers.ARP) string {
	if arp == nil {
		return "unknown"
	}
	srcIP := net.IP(arp.SourceProtAddress)
	dstIP := net.IP(arp.DstProtAddress)
	sameSender := srcIP.Equal(dstIP) && !srcIP.IsUnspecified()

	switch arp.Operation {
	case layers.ARPRequest:
		if srcIP.IsUnspecified() {
			return "probe"
		}
		if sameSender {
			return "announce"
		}
		return "request"
	case layers.ARPReply:
		if sameSender {
			return "gratuitous-reply"
		}
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

func trimLocal(name string) string {
	n := strings.TrimSpace(name)
	n = strings.TrimSuffix(n, ".")
	n = strings.ToLower(n)
	n = strings.TrimSuffix(n, ".local")
	return n
}

// split key-value from key=value to key = "value"
func splitKV(b []byte) (string, string, bool) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", "", false
	}
	i := bytes.IndexByte([]byte(s), '=')
	if i < 0 {
		return s, "", true
	}
	return s[:i], s[i+1:], true
}

func portKey(p uint16) string { return strconv.Itoa(int(p)) }
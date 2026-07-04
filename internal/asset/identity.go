package asset

import (
	"net"
	"strings"
)

func macKey(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return ""
	}
	return "mac:" + strings.ToLower(mac.String())
}

func GenerateAssetID(mac net.HardwareAddr) AssetID {
	return AssetID(macKey(mac))
}
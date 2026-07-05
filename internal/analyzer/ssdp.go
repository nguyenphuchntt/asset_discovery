package analyzer

import (
	"bufio"
	"bytes"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

// Simple Service Discovery Protocol
// join network -> notify its services
// HTTP via UDP

type SSDPAnalyzer struct{}

func NewSSDPAnalyzer() *SSDPAnalyzer { return &SSDPAnalyzer{} }

func (s *SSDPAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || (udp.SrcPort != 1900 && udp.DstPort != 1900) {
		return nil
	}
	payload := udp.Payload
	// SSDP messages

	//NOTIFY * HTTP/1.1
	isSSDPLike := bytes.HasPrefix(payload, []byte("NOTIFY ")) || bytes.HasPrefix(payload, []byte("HTTP/")) 
	if len(payload) == 0 || !isSSDPLike {
		return nil
	}
	// Search for services
	if bytes.HasPrefix(payload, []byte("M-SEARCH ")) {
		return nil
	}
	headers := parseSSDPHeaders(payload)
	if len(headers) == 0 {
		return nil
	}
	mac, ok := ethSrcMAC(packet)
	if !ok {
		return nil
	}
	observedAt := packet.Metadata().Timestamp
	obs := asset.Observation{
		Source:     asset.SourceSSDP,
		ObservedAt: observedAt,
		MAC:        asset.CloneMAC(mac),
	}
	fillObsIPs(&obs, packet, observedAt)
	applyServerScalars(&obs, headers["server"])
	obs.DeviceType = ssdpDeviceType(headers["st"], headers["nt"])

	if svc := ssdpService(headers, observedAt); svc != nil {
		obs.Services = []asset.Service{*svc}
	}

	if !obs.Valid() {
		return nil
	}
	return []asset.Observation{obs}
}

func parseSSDPHeaders(payload []byte) map[string]string {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	first := true
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			break // blank line = end of headers
		}
		if first {
			first = false
			continue // status/request line
		}
		k, v, ok := splitKV([]byte(line))
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if _, exists := headers[k]; !exists {
			headers[k] = v
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

//SERVER: Linux/3.10 UPnP/1.0 MiniUPnPd/2.2.1
func applyServerScalars(obs *asset.Observation, server string) {
	if server == "" {
		return
	}
	for _, tok := range strings.Fields(server) {
		name, ver, _ := strings.Cut(tok, "/")
		if name == "" {
			continue
		}
		switch strings.ToLower(name) {
		case "linux", "freebsd", "openbsd", "netbsd", "darwin":
			if obs.OS == "" {
				obs.OS = name
				if ver != "" && obs.Extra["ssdp_os_version"] == nil {
					if obs.Extra == nil {
						obs.Extra = make(map[string]any)
					}
					obs.Extra["ssdp_os_version"] = ver
				}
			}
		case "upnp": // no value UPnP/1.0
		default:
			if obs.Model == "" && ver != "" {
				obs.Model = name
			}
		}
	}
}

func ssdpDeviceType(st, nt string) string {
	v := st
	if v == "" {
		v = nt
	}
	if v == "" {
		return ""
	}
	lower := strings.ToLower(v)
	switch {
	case strings.Contains(lower, "internetgateway"):
		return "router"
	case strings.Contains(lower, "mediaserver"):
		return "nas"
	case strings.Contains(lower, "mediarenderer"):
		return "smart-tv"
	case strings.Contains(lower, "printer"):
		return "printer"
	case strings.Contains(lower, "basic"):
		return "upnp-device"
	}
	return ""
}

func ssdpService(headers map[string]string, observedAt time.Time) *asset.Service {
	loc := headers["location"]
	if loc == "" {
		return nil
	}
	u, err := url.Parse(loc)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	p := u.Port()
	if p == "" {
		return nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return nil
	}
	name := u.Scheme
	if name == "" {
		name = "upnp"
	}
	return &asset.Service{
		Protocol: "tcp",
		Port:     uint16(n),
		Name:     name,
		LastSeen: observedAt,
	}
}
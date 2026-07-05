package analyzer

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
)

// Port-to-name mapping for common TCP/UDP services. We keep a compact
// subset (~50 ports) that are most relevant for client-use inference.
// Full /etc/services is not embedded to keep the binary size small.
var commonServiceName = map[uint16]string{
	// Web
	80:   "http",
	443:  "https",
	8080: "http-alt",
	8443: "https-alt",

	// Mail
	25:   "smtp",
	110:  "pop3",
	143:  "imap",
	587:  "submission",
	993:  "imaps",
	995:  "pop3s",

	// File sharing
	445: "smb",
	139: "netbios-ssn",
	137: "netbios-ns",
	138: "netbios-dgm",
	548: "afp",
	2049: "nfs",

	// Remote access
	22:   "ssh",
	23:   "telnet",
	3389: "rdp",
	5900: "vnc",
	5901: "vnc-1",

	// DNS / DHCP
	53:  "dns",
	67:  "dhcp-server",
	68:  "dhcp-client",
	546: "dhcpv6-client",
	547: "dhcpv6-server",

	// Databases
	3306: "mysql",
	5432: "postgresql",
	27017: "mongodb",
	6379: "redis",
	1433: "mssql",

	// Messaging / streaming
	5222: "xmpp",
	1935: "rtmp",
	554:  "rtsp",

	// Discovery
	5353: "mdns",
	1900: "ssdp",
	3702: "ws-discovery",

	// Infrastructure
	123:   "ntp",
	389:   "ldap",
	636:   "ldaps",
	514:   "syslog",
	162:   "snmp-trap",
	161:   "snmp",
	179:   "bgp",
	830:   "netconf",
	500:   "isakmp",
	4500:  "ipsec-nat-t",

	// Container / orchestration
	6443: "kube-apiserver",
	2379: "etcd",
	2380: "etcd-peer",
	10250: "kubelet",
	8472: "flannel-vxlan",

	// HTTP proxies / caches
	3128: "squid",
	1080: "socks",
}

func guessServiceName(port uint16, protocol string) string {
	if n, ok := commonServiceName[port]; ok {
		return n
	}
	return ""
}

const DefaultEthernetThrottle = 60 * time.Second

// EthernetAnalyzer passively tracks every device that sends ANY packet on
// the LAN, regardless of protocol. Every Ethernet frame has a source MAC;
// by extracting it from ALL traffic (not just ARP/DHCP/mDNS), we get a
// continuous presence signal for devices that are online but idle or using
// protocols we don't have analyzers for (HTTP, NTP, SSH, ICMP, …).
//
// MAC throttle: to avoid flooding the manager with per-packet observations,
// we only emit once per MAC per throttle interval. The lastEmit map is
// keyed by MAC string (stable, no allocation on lookup).
//
// This analyzer is STATEFUL — it breaks the stateless contract of the
// other analyzers. This is an explicit trade-off: presence tracking
// requires memory of when each MAC was last seen. The map is bounded
// by the number of unique MACs on the LAN (typically <1000), so memory
// is not a concern.
//
// Thread safety: currently the pipeline runs with workers=1, but we use
// sync.Map to be safe if workers is ever increased.
type EthernetAnalyzer struct {
	lastEmit      sync.Map // map[string]time.Time — MAC → last emission wall-clock
	throttleAfter time.Duration
}

func NewEthernetAnalyzer() *EthernetAnalyzer {
	return &EthernetAnalyzer{throttleAfter: DefaultEthernetThrottle}
}

func (e *EthernetAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok || !isUsableMAC(eth.SrcMAC) {
		return nil
	}

	// MAC throttle — skip if we emitted for this MAC recently.
	macKey := eth.SrcMAC.String()
	now := time.Now()
	throttled := false
	if last, ok := e.lastEmit.Load(macKey); ok {
		if now.Sub(last.(time.Time)) < e.throttleAfter {
			throttled = true
		}
	}
	if !throttled {
		e.lastEmit.Store(macKey, now)
	}

	observedAt := packet.Metadata().Timestamp

	// 1) Presence + IP observation (skipped when throttled).
	var obs asset.Observation
	if !throttled {
		obs = asset.Observation{
			Source:     asset.SourceEthernet,
			ObservedAt: observedAt,
			MAC:        asset.CloneMAC(eth.SrcMAC),
		}

		if v4 := packet.Layer(layers.LayerTypeIPv4); v4 != nil {
			if s := asset.NormalizeIPv4Addr(v4.(*layers.IPv4).SrcIP); s != "" {
				obs.IPv4s = map[string]asset.IPEntry{s: {
					FirstSeen: observedAt,
					LastSeen:  observedAt,
					IsActive:  true,
				}}
			}
		}
		if v6 := packet.Layer(layers.LayerTypeIPv6); v6 != nil {
			src := v6.(*layers.IPv6).SrcIP
			if src != nil && !src.IsLinkLocalUnicast() {
				if s := asset.NormalizeIPv6Addr(src); s != "" {
					obs.IPv6s = map[string]asset.IPEntry{s: {
						FirstSeen: observedAt,
						LastSeen:  observedAt,
						IsActive:  true,
					}}
				}
			}
		}
	}

	// 2) TCP SYN tracking — not throttled. Every SYN to a new dest port
	// emits a Service with IsClient=true so we build a "services used"
	// catalog alongside the "services provided" catalog from mDNS/SSDP.
	out, ok := e.detectSYN(packet, observedAt)
	if ok {
		if !throttled && obs.Valid() {
			obs.Services = out
			return []asset.Observation{obs}
		}
		// Throttled but SYN detected — emit a standalone service observation.
		srvObs := asset.Observation{
			Source:     asset.SourceEthernet,
			ObservedAt: observedAt,
			MAC:        asset.CloneMAC(eth.SrcMAC),
			Services:   out,
		}
		return []asset.Observation{srvObs}
	}

	if throttled || !obs.Valid() {
		return nil
	}
	return []asset.Observation{obs}
}

// Reset clears the throttle map. Useful for tests.
func (e *EthernetAnalyzer) Reset() {
	e.lastEmit = sync.Map{}
}

// detectSYN inspects a TCP SYN (not SYN-ACK) and returns a Service entry
// if the destination port is a known service. The SYN packet is emitted by
// a *client* connecting to a *server*, so we mark IsClient=true.
func (e *EthernetAnalyzer) detectSYN(packet gopacket.Packet, observedAt time.Time) ([]asset.Service, bool) {
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !tcp.SYN || tcp.ACK {
		return nil, false
	}
	port := uint16(tcp.DstPort)
	name := guessServiceName(port, "tcp")
	if name == "" {
		return nil, false
	}
	return []asset.Service{{
		Protocol: "tcp",
		Port:     port,
		Name:     name,
		LastSeen: observedAt,
		IsClient: true,
	}}, true
}

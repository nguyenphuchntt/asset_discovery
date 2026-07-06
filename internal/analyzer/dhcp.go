package analyzer

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/utils"
)

type DHCPAnalyzer struct{}

func NewDHCPAnalyzer() *DHCPAnalyzer { return &DHCPAnalyzer{} }

func (d *DHCPAnalyzer) Analyze(packet gopacket.Packet) []asset.Observation {
	ctx := DecodePacketCtx(packet)
	return d.AnalyzeCtx(&ctx)
}

func (d *DHCPAnalyzer) AnalyzeCtx(ctx *PacketCtx) []asset.Observation {
	if ctx == nil || ctx.DHCPv4 == nil || !isUsableMAC(ctx.DHCPv4.ClientHWAddr) {
		return nil
	}
	dhcp := ctx.DHCPv4
	observedAt := ctx.ObservedAt()
	ip := selectDHCPv4IP(dhcp)
	hostname := utils.DHCPv4Hostname(dhcp)

	obs := asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: observedAt,
		MAC:        asset.CloneMAC(dhcp.ClientHWAddr),
		Extra:      dhcpv4Extras(dhcp),
	}
	if hostname != "" {
		obs.Hostnames = []string{hostname}
	}
	if ip4 := asset.NormalizeIPv4Addr(ip); ip4 != "" {
		obs.IPv4s = map[string]asset.IPEntry{ip4: {
			FirstSeen: observedAt,
			LastSeen:  observedAt,
			Lease:     dhcpv4Lease(dhcp),
			IsActive:  true,
		}}
	}
	return []asset.Observation{obs}
}

func dhcpv4Lease(dhcp *layers.DHCPv4) time.Duration {
	opt, ok := utils.FindDHCPOption(dhcp, layers.DHCPOptLeaseTime)
	if !ok || len(opt.Data) < 4 {
		return 0
	}
	secs := uint32(opt.Data[0])<<24 | uint32(opt.Data[1])<<16 |
		uint32(opt.Data[2])<<8 | uint32(opt.Data[3]) // merge into uint32
	return time.Duration(secs) * time.Second
}

func selectDHCPv4IP(dhcp *layers.DHCPv4) net.IP {
	if dhcp == nil {
		return nil
	}
	if asset.NormalizeIPv4Addr(dhcp.YourClientIP) != "" {
		return dhcp.YourClientIP
	}
	if req := utils.DHCPv4RequestedIP(dhcp); asset.NormalizeIPv4Addr(req) != "" {
		return req
	}
	if asset.NormalizeIPv4Addr(dhcp.ClientIP) != "" {
		return dhcp.ClientIP
	}
	return nil
}

func dhcpv4Extras(dhcp *layers.DHCPv4) map[string]any {
	extra := map[string]any{
		"dhcpv4_message_type": dhcpMessageTypeName(utils.DHCPv4MessageType(dhcp)),
	}
	if v := utils.DHCPv4ClassID(dhcp); v != "" {
		extra["dhcpv4_vendor_class"] = v // e.g: MSFT 5.0/ udhcp
	}
	if v := utils.DHCPv4ServerID(dhcp); v != nil {
		if s := asset.NormalizeIPv4Addr(v); s != "" {
			extra["dhcpv4_server"] = s // ip dhcp server
		}
	}
	if names := utils.DHCPv4DNSServers(dhcp); len(names) > 0 {
		out := make([]string, 0, len(names))
		for _, ip := range names {
			if s := asset.NormalizeIPv4Addr(ip); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			extra["dhcpv4_dns_servers"] = out
		}
	}
	if v := utils.DHCPv4DomainName(dhcp); v != "" {
		extra["dhcpv4_domain"] = v // e.g home.local
	}
	if pri := utils.DHCPv4ParamRequestList(dhcp); len(pri) > 0 {
		extra["dhcpv4_param_request_list"] = paramRequestListFingerprint(pri)
	}
	if v := utils.DHCPv4RelayInfo(dhcp); len(v) > 0 {
		extra["dhcpv4_relay_agent"] = v
	}
	return extra
}

// []{1, 2, 3} to "1, 2, 3"
func paramRequestListFingerprint(pri []byte) string {
	const maxCodes = 16
	n := len(pri)
	if n > maxCodes {
		n = maxCodes
	}
	out := make([]byte, 0, n*4)
	for i := 0; i < n; i++ {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendUint(out, uint(pri[i]))
	}
	return string(out)
}

func appendUint(b []byte, v uint) []byte {
	if v == 0 {
		return append(b, '0')
	}
	var buf [3]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(b, buf[i:]...)
}
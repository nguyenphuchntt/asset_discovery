package asset

import (
	"net"
	"strconv"
	"time"
)

// update an Asset with a new Observation
func mergeObservation(a *Asset, obs Observation) (changed bool) {
	var c bool

	a.MACs, c = mergeMACs(a.MACs, obs.Attrs.MACs...)
	changed = changed || c
	a.IPv4s, c = mergeIPv4s(a.IPv4s, obs.Attrs.IPv4s...)
	changed = changed || c
	a.IPv6s, c = mergeIPv6s(a.IPv6s, obs.Attrs.IPv6s...)
	changed = changed || c

	a.Hostnames, c = mergeStrings(a.Hostnames, obs.Attrs.Hostnames...)
	changed = changed || c
	a.FQDNs, c = mergeStrings(a.FQDNs, obs.Attrs.FQDNs...)
	changed = changed || c

	a.Vendors, c = mergeVendors(a.Vendors, obs.Attrs.Vendors...)
	changed = changed || c
	a.Services, c = mergeServices(a.Services, obs.Attrs.Services...)
	changed = changed || c
	a.Sources, c = mergeSources(a.Sources, obs.Source)
	changed = changed || c

	if touchTimestamps(a, obs.ObservedAt) {
		changed = true
	}
	return changed
}

// merge two assets
func mergeAssets(primary, secondary *Asset) (changed bool) {
	var c bool

	primary.MACs, c = mergeMACs(primary.MACs, secondary.MACs...)
	changed = changed || c
	primary.IPv4s, c = mergeIPv4s(primary.IPv4s, secondary.IPv4s...)
	changed = changed || c
	primary.IPv6s, c = mergeIPv6s(primary.IPv6s, secondary.IPv6s...)
	changed = changed || c
	primary.Hostnames, c = mergeStrings(primary.Hostnames, secondary.Hostnames...)
	changed = changed || c
	primary.FQDNs, c = mergeStrings(primary.FQDNs, secondary.FQDNs...)
	changed = changed || c
	primary.Vendors, c = mergeVendors(primary.Vendors, secondary.Vendors...)
	changed = changed || c
	primary.Services, c = mergeServices(primary.Services, secondary.Services...)
	changed = changed || c
	primary.Sources, c = mergeSources(primary.Sources, secondary.Sources...)
	changed = changed || c

	if !secondary.FirstSeen.IsZero() && (primary.FirstSeen.IsZero() || secondary.FirstSeen.Before(primary.FirstSeen)) {
		primary.FirstSeen = secondary.FirstSeen
		changed = true
	}
	if secondary.LastSeen.After(primary.LastSeen) {
		primary.LastSeen = secondary.LastSeen
		changed = true
	}
	return changed
}

// update first_seen/ last_seen
func touchTimestamps(a *Asset, at time.Time) (changed bool) {
	if at.IsZero() {
		return false
	}
	if a.FirstSeen.IsZero() || at.Before(a.FirstSeen) {
		a.FirstSeen = at
		changed = true
	}
	if at.After(a.LastSeen) {
		a.LastSeen = at
		changed = true
	}
	return changed
}

// merge MACs
func mergeMACs(existing []net.HardwareAddr, incoming ...net.HardwareAddr) (result []net.HardwareAddr, changed bool) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, m := range existing {
		seen[NormalizeMACAddr(m)] = struct{}{}
	}
	for _, m := range incoming {
		k := NormalizeMACAddr(m)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		existing = append(existing, cloneHardwareAddr(m))
		changed = true
	}
	return existing, changed
}

// merge IPv4s
func mergeIPv4s(existing []net.IP, incoming ...net.IP) (result []net.IP, changed bool) {
	return mergeIPs(existing, incoming, NormalizeIPv4Addr, net.IP.To4)
}

// merge IPv6s
func mergeIPv6s(existing []net.IP, incoming ...net.IP) (result []net.IP, changed bool) {
	return mergeIPs(existing, incoming, NormalizeIPv6Addr, net.IP.To16)
}

// merge IPs
func mergeIPs(existing []net.IP, incoming []net.IP, norm func(net.IP) string, canon func(net.IP) net.IP) ([]net.IP, bool) {
	changed := false
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, ip := range existing {
		seen[norm(ip)] = struct{}{}
	}
	for _, ip := range incoming {
		k := norm(ip)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		existing = append(existing, cloneIP(canon(ip)))
		changed = true
	}
	return existing, changed
}

// clone HardwareAddr
func cloneHardwareAddr(mac net.HardwareAddr) net.HardwareAddr {
	if mac == nil {
		return nil
	}
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}

// cloneIP
func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

// cloneMACs
func cloneMACs(src []net.HardwareAddr) []net.HardwareAddr {
	if src == nil {
		return nil
	}
	out := make([]net.HardwareAddr, len(src))
	for i, m := range src {
		out[i] = cloneHardwareAddr(m)
	}
	return out
}

// cloneIPs
func cloneIPs(src []net.IP) []net.IP {
	if src == nil {
		return nil
	}
	out := make([]net.IP, len(src))
	for i, ip := range src {
		out[i] = cloneIP(ip)
	}
	return out
}

// merge string (deduplicate, order-preserving)
func mergeStrings(existing []string, incoming ...string) (result []string, changed bool) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, v := range existing {
		seen[v] = struct{}{}
	}
	for _, v := range incoming {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		existing = append(existing, v)
		changed = true
	}
	return existing, changed
}

// merge vendor (deduplicate by (Source, Value))
func mergeVendors(existing []Vendor, incoming ...Vendor) (result []Vendor, changed bool) {
	key := func(v Vendor) string { return v.Source + "\x00" + v.Value } // null character
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, v := range existing {
		seen[key(v)] = struct{}{}
	}
	for _, v := range incoming {
		if v.Value == "" {
			continue
		}
		k := key(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		existing = append(existing, v)
		changed = true
	}
	return existing, changed
}

// merge services (deduplicate by (protocol, port))
func mergeServices(existing []Service, incoming ...Service) (result []Service, changed bool) {
	key := func(s Service) string { return s.Protocol + ":" + strconv.Itoa(int(s.Port)) }
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, s := range existing {
		seen[key(s)] = struct{}{}
	}
	for _, s := range incoming {
		if s.Protocol == "" && s.Port == 0 {
			continue
		}
		k := key(s)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		existing = append(existing, s)
		changed = true
	}
	return existing, changed
}

// merge Observation source
func mergeSources(existing []ObservationSource, incoming ...ObservationSource) (result []ObservationSource, changed bool) {
	seen := make(map[ObservationSource]struct{}, len(existing)+len(incoming))
	for _, s := range existing {
		seen[s] = struct{}{}
	}
	for _, s := range incoming {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		existing = append(existing, s)
		changed = true
	}
	return existing, changed
}

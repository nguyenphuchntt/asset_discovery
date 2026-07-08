package asset

import (
	"net"
	"time"
	"strconv"
)

func NormalizeMACAddr(mac net.HardwareAddr) string {
	if mac == nil {
		return ""
	}
	return mac.String()
}

func NormalizeIPv4Addr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ""
}

func NormalizeIPv6Addr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return v6.String()
	}
	return ""
}

func CloneMAC(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) == 0 {
		return nil
	}
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}

func cloneIPMap(src map[string]IPEntry) map[string]IPEntry {
	if src == nil {
		return nil
	}
	out := make(map[string]IPEntry, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// MergeIPMap exports mergeIPMap for use in tests (via export_test.go).
func MergeIPMap(dst *map[string]IPEntry, src map[string]IPEntry, now time.Time) (changed bool, added []string) {
	return mergeIPMap(dst, src, now)
}

func mergeIPMap(dst *map[string]IPEntry, src map[string]IPEntry, now time.Time) (changed bool, added []string) {
	if len(src) == 0 {
		return false, nil
	}
	if *dst == nil {
		*dst = make(map[string]IPEntry, len(src))
	}
	for ip, in := range src {
		if ip == "" {
			continue
		}
		existing, ok := (*dst)[ip]
		if !ok {
			in.FirstSeen = now
			in.IsActive = true
			(*dst)[ip] = in
			changed = true
			added = append(added, ip)
			continue
		}
		if in.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = in.LastSeen
			changed = true
		}
		if in.Lease > 0 && in.Lease > existing.Lease {
			existing.Lease = in.Lease
			changed = true
		}
		if !existing.IsActive {
			existing.IsActive = true
			changed = true
		}
		(*dst)[ip] = existing
	}
	return changed, added
}

// TouchTimestamps exports touchTimestamps for use in tests.
func TouchTimestamps(a *Asset, at time.Time) bool {
	return touchTimestamps(a, at)
}

func touchTimestamps(a *Asset, at time.Time) bool {
	if at.IsZero() {
		return false
	}
	changed := false
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

// MergeExtras exports mergeExtras for use in tests.
func MergeExtras(dst *map[string]any, src map[string]any) bool {
	return mergeExtras(dst, src)
}

func mergeExtras(dst *map[string]any, src map[string]any) bool {
	if len(src) == 0 {
		return false
	}
	if *dst == nil {
		*dst = make(map[string]any, len(src))
	}
	changed := false
	for k, v := range src {
		if v == nil {
			continue
		}
		existing, ok := (*dst)[k]
		if !ok {
			(*dst)[k] = v
			changed = true
			continue
		}
		switch ev := existing.(type) {
		case []any:
			if nv, ok := v.([]any); ok {
				(*dst)[k] = append(ev, nv...)
				changed = true
				continue
			}
			if nv, ok := v.([]string); ok {
				merged := ev
				for _, s := range nv {
					if s == "" {
						continue
					}
					merged = append(merged, s)
				}
				(*dst)[k] = merged
				changed = true
				continue
			}
		case []string:
			if nv, ok := v.([]string); ok {
				merged, c, _ := mergeStrings(ev, nv...)
				if c {
					(*dst)[k] = merged
					changed = true
				}
				continue
			}
			if nv, ok := v.([]any); ok {
				promoted := make([]any, len(ev))
				for i, s := range ev {
					promoted[i] = s
				}
				(*dst)[k] = append(promoted, nv...)
				changed = true
				continue
			}
		}
	}
	return changed
}

// MergeStrings exports mergeStrings for use in tests.
func MergeStrings(existing []string, incoming ...string) (out []string, changed bool, added []string) {
	return mergeStrings(existing, incoming...)
}

func mergeStrings(existing []string, incoming ...string) (out []string, changed bool, added []string) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, v := range existing {
		seen[v] = struct{}{}
	}
	out = existing
	for _, v := range incoming {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
		added = append(added, v)
		changed = true
	}
	return out, changed, added
}

// MergeServices exports mergeServices for use in tests.
func MergeServices(existing []Service, incoming ...Service) (out []Service, changed bool, added []Service) {
	return mergeServices(existing, incoming...)
}

func mergeServices(existing []Service, incoming ...Service) (out []Service, changed bool, added []Service) {
	key := func(s Service) string {
		if s.IsClient {
			return s.Protocol + ":" + strconv.Itoa(int(s.Port)) + ":client"
		}
		return s.Protocol + ":" + strconv.Itoa(int(s.Port)) + ":server"
	}
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, s := range existing {
		seen[key(s)] = struct{}{}
	}
	out = existing
	for _, s := range incoming {
		if s.Protocol == "" && s.Port == 0 {
			continue
		}
		k := key(s)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
		added = append(added, s)
		changed = true
	}
	return out, changed, added
}
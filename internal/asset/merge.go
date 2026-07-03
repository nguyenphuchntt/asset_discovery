package asset

import (
	"net"
	"strconv"
	"time"
)

// mergeObservation folds an Observation into an existing Asset.
//
// Returns true if anything in the asset changed (used by the manager to
// decide whether to emit an EventAssetUpdated and to mark the asset dirty).
//
// Callers must hold whatever lock protects `a`.
func mergeObservation(a *Asset, obs Observation) bool {
	changed := false
	var c bool

	// 1. Identifiers drive the canonical identifier slices.
	for _, id := range obs.Identifiers {
		switch id.Type {
		case IdentifierMAC:
			mac, err := net.ParseMAC(id.Value)
			if err != nil {
				continue
			}
			a.MACs, c = mergeMACs(a.MACs, mac)
			changed = changed || c

		case IdentifierIPv4:
			ip := net.ParseIP(id.Value)
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			a.IPv4s, c = mergeIPv4s(a.IPv4s, v4)
			changed = changed || c

		case IdentifierIPv6:
			ip := net.ParseIP(id.Value)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				continue // skip v4-mapped v6
			}
			v6 := ip.To16()
			if v6 == nil {
				continue
			}
			a.IPv6s, c = mergeIPv6s(a.IPv6s, v6)
			changed = changed || c
		}
	}

	// 2. Typed optional fields.
	if len(obs.Hostnames) > 0 {
		a.Hostnames, c = mergeStrings(a.Hostnames, obs.Hostnames...)
		changed = changed || c
	}
	if len(obs.Services) > 0 {
		a.Services, c = mergeServices(a.Services, obs.Services...)
		changed = changed || c
	}

	// 3. Free-form extras.
	if mergeExtras(&a.Extra, obs.Extra) {
		changed = true
	}

	// 4. Timestamps.
	if touchTimestamps(a, obs.ObservedAt) {
		changed = true
	}

	return changed
}

// mergeAssets folds every typed field of `secondary` into `primary`. Called
// when the resolver reports that one observation bridges two previously-
// separate assets — they should converge on `primary` and `secondary` is
// discarded.
//
// Semantics:
//   - Identifier slices: dedup union.
//   - Typed optional scalars (MACVendor, OS): first non-empty wins.
//   - Extra: same first-wins / slice-append rules as mergeExtras.
//   - FirstSeen/LastSeen: take the earliest/latest across both.
func mergeAssets(primary, secondary *Asset) bool {
	changed := false
	var c bool

	primary.MACs, c = mergeMACs(primary.MACs, secondary.MACs...)
	changed = changed || c
	primary.IPv4s, c = mergeIPv4s(primary.IPv4s, secondary.IPv4s...)
	changed = changed || c
	primary.IPv6s, c = mergeIPv6s(primary.IPv6s, secondary.IPv6s...)
	changed = changed || c

	primary.Hostnames, c = mergeStrings(primary.Hostnames, secondary.Hostnames...)
	changed = changed || c
	primary.Services, c = mergeServices(primary.Services, secondary.Services...)
	changed = changed || c

	if mergeExtras(&primary.Extra, secondary.Extra) {
		changed = true
	}

	if primary.MACVendor == "" && secondary.MACVendor != "" {
		primary.MACVendor = secondary.MACVendor
		changed = true
	}
	if primary.OS == "" && secondary.OS != "" {
		primary.OS = secondary.OS
		changed = true
	}

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

// touchTimestamps widens FirstSeen/LastSeen to include `at`.
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

// mergeExtras merges src into *dst using simple, predictable rules:
//   - If a key is absent from dst, insert it.
//   - If both sides are []any, append.
//   - Otherwise, the existing value wins (so a later observation cannot
//     overwrite a more authoritative earlier one — first non-empty wins
//     in practice because nil/empty entries don't enter the loop).
//
// Returning a value of nil from a merge is intentionally a no-op; the field
// is only "changed" when something is actually added.
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
		if eSlice, ok := existing.([]any); ok {
			if nSlice, ok := v.([]any); ok {
				(*dst)[k] = append(eSlice, nSlice...)
				changed = true
			}
		}
	}
	return changed
}

// -----------------------------------------------------------------------------
// Slice merge helpers (dedup with canonical keys, return changed flag)
// -----------------------------------------------------------------------------

func mergeMACs(existing []net.HardwareAddr, incoming ...net.HardwareAddr) ([]net.HardwareAddr, bool) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, m := range existing {
		seen[NormalizeMACAddr(m)] = struct{}{}
	}
	changed := false
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

func mergeIPv4s(existing []net.IP, incoming ...net.IP) ([]net.IP, bool) {
	return mergeIPs(existing, incoming, NormalizeIPv4Addr, net.IP.To4)
}

func mergeIPv6s(existing []net.IP, incoming ...net.IP) ([]net.IP, bool) {
	return mergeIPs(existing, incoming, NormalizeIPv6Addr, net.IP.To16)
}

func mergeIPs(existing []net.IP, incoming []net.IP, norm func(net.IP) string, canon func(net.IP) net.IP) ([]net.IP, bool) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, ip := range existing {
		seen[norm(ip)] = struct{}{}
	}
	changed := false
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

// mergeStrings is a dedup, order-preserving union of string slices. Empty
// incoming values are skipped.
func mergeStrings(existing []string, incoming ...string) ([]string, bool) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, v := range existing {
		seen[v] = struct{}{}
	}
	changed := false
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

// mergeServices dedups by (Protocol, Port). Name and Version are kept from the
// first observation that supplies them.
func mergeServices(existing []Service, incoming ...Service) ([]Service, bool) {
	key := func(s Service) string { return s.Protocol + ":" + strconv.Itoa(int(s.Port)) }
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, s := range existing {
		seen[key(s)] = struct{}{}
	}
	changed := false
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

// -----------------------------------------------------------------------------
// Clone helpers (used by snapshot)
// -----------------------------------------------------------------------------

func cloneHardwareAddr(mac net.HardwareAddr) net.HardwareAddr {
	if mac == nil {
		return nil
	}
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

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
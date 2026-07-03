package asset

import (
	"net"
	"slices"
	"time"
)

// AssetSnapshot is an immutable copy of an Asset taken at a point in time.
// Persister, API, and CLI all read snapshots — never live *Asset values —
// so that mutations of the underlying asset can't leak out.
//
// The shape mirrors Asset exactly. Maps and slices are deep-copied so callers
// can freely modify the snapshot without affecting the live state.
type AssetSnapshot struct {
	ID AssetID

	MACs  []net.HardwareAddr
	IPv4s []net.IP
	IPv6s []net.IP

	Hostnames []string
	Services  []Service
	MACVendor string
	OS        string

	Extra map[string]any

	FirstSeen time.Time
	LastSeen  time.Time
	Status    Status
}

func (a *Asset) Snapshot() AssetSnapshot {
	return AssetSnapshot{
		ID: a.ID,

		MACs:  cloneMACs(a.MACs),
		IPv4s: cloneIPs(a.IPv4s),
		IPv6s: cloneIPs(a.IPv6s),

		Hostnames: slices.Clone(a.Hostnames),
		Services:  slices.Clone(a.Services),
		MACVendor: a.MACVendor,
		OS:        a.OS,

		Extra: cloneExtras(a.Extra),

		FirstSeen: a.FirstSeen,
		LastSeen:  a.LastSeen,
		Status:    a.Status,
	}
}

// cloneExtras makes a shallow copy of the map. Values are intentionally not
// deep-cloned — callers receive the same strings, slices, structs as the
// producer put in. If a future Extra value type needs deep-copy semantics,
// extend this function.
func cloneExtras(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
package asset

import (
	"net"
	"slices"
	"time"
)

type AssetSnapshot struct {
	ID AssetID

	MAC   net.HardwareAddr
	IPv4s map[string]IPEntry
	IPv6s map[string]IPEntry

	Hostnames  []string
	Services   []Service
	MACVendor  string
	DeviceType string
	Model      string
	OS         string

	Extra map[string]any

	FirstSeen time.Time
	LastSeen  time.Time
	SeenCount uint64
	Status    Status
}

// Snapshot (deep copy)
func (a *Asset) Snapshot() AssetSnapshot {
	return AssetSnapshot{
		ID: a.ID,

		MAC:   CloneMAC(a.MAC),
		IPv4s: cloneIPMap(a.IPv4s),
		IPv6s: cloneIPMap(a.IPv6s),

		Hostnames: slices.Clone(a.Hostnames),
		Services:  slices.Clone(a.Services),
		MACVendor: a.MACVendor,
		DeviceType: a.DeviceType,
		Model:     a.Model,
		OS:        a.OS,

		Extra: cloneExtras(a.Extra),

		FirstSeen: a.FirstSeen,
		LastSeen:  a.LastSeen,
		SeenCount: a.SeenCount,
		Status:    a.Status,
	}
}

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
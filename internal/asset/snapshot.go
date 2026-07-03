package asset

import (
	"net"
	"slices"
	"time"
)

type AssetSnapshot struct {
	ID AssetID

	// attr
	MACs  []net.HardwareAddr
	IPv4s []net.IP
	IPv6s []net.IP

	Hostnames []string
	FQDNs     []string

	Vendors  []Vendor
	Services []Service
	Sources  []ObservationSource

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
		FQDNs:     slices.Clone(a.FQDNs),
		Vendors:   slices.Clone(a.Vendors),
		Services:  slices.Clone(a.Services),
		Sources:   slices.Clone(a.Sources),

		FirstSeen: a.FirstSeen,
		LastSeen:  a.LastSeen,
		Status:    a.Status,
	}
}

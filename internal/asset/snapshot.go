package asset

import (
	"slices"
	"time"
)

type AssetSnapshot struct {
	ID AssetID

	// attr
	MACs      []string
	IPv4s     []string
	IPv6s     []string

	Hostnames []string
	FQDNs     []string

	Vendors   []Vendor
	Services  []Service
	Sources   []ObservationSource

	FirstSeen time.Time
	LastSeen  time.Time
	Status    Status
}

func (a *Asset) Snapshot() AssetSnapshot {
	return AssetSnapshot{
		ID: a.ID,

		MACs:      slices.Clone(a.MACs),
		IPv4s:     slices.Clone(a.IPv4s),
		IPv6s:     slices.Clone(a.IPv6s),
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

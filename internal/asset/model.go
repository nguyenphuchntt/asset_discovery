package asset

import "time"

type AssetID string

type Status string

const (
	StatusOnline  Status = "online"
	StatusOffline Status = "offline"
)

type Asset struct {
	ID AssetID

	MACs      []string
	IPv4s     []string
	IPv6s     []string
	Hostnames []string
	FQDNs     []string
	Vendors   []Vendor
	Services  []Service
	Sources   []ObservationSource

	FirstSeen  time.Time
	LastSeen   time.Time
	Status     Status
	Confidence int
}

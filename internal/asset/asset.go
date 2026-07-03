package asset

import (
	"net"
	"time"
)

type AssetID string

type Status string

const (
	StatusOnline Status = "online"
	StatusOffline Status = "offline"
)

type Asset struct {
	ID AssetID

	MACs  []net.HardwareAddr
	IPv4s []net.IP
	IPv6s []net.IP

	Hostnames []string
	FQDNs []string
	
	Vendors []Vendor
	Services []Service
	Sources []ObservationSource

	FirstSeen time.Time
	LastSeen time.Time
	Status Status // on/off
}

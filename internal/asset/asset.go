package asset

import (
	"net"
	"time"
)

type AssetID string

type Status string

const (
	StatusOnline  Status = "online"
	StatusOffline Status = "offline"
)

type Service struct {
	Protocol string // tcp/ udp
	Port     uint16
	Name     string // http/ ssh/ ...
	Version  string
	Product  string // e.g. nginx
	Vendor   string // F5 Inc
	Banner   string // raw first response
	IsActive bool   // true if host replied
	LastSeen time.Time

	IsClient bool
}

type IPEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time
	Lease     time.Duration
	IsActive  bool
}

type Asset struct {
	ID AssetID

	MAC net.HardwareAddr

	IPv4s map[string]IPEntry
	IPv6s map[string]IPEntry

	Hostnames []string
	Services []Service

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
// Package asset is the domain core of the passive discovery system.
//
// An Asset represents a single network device observed through one or more
// passive observation sources (ARP, DHCP, DNS, mDNS, ...).
//
// The model is intentionally minimal:
//   - Core identifiers: MACs, IPv4s, IPv6s.
//   - A small set of typed optional fields: Hostnames, Services, MACVendor, OS.
//   - A free-form Extra map for anything else (device_type, model,
//     dhcp_fingerprint, snmp_sysdescr, fqdn, tags, ...) — analyzers and
//     enrichment stages can append their own keys without changing this file.
package asset

import (
	"net"
	"time"
)

type AssetID string

// Status reflects the most recent lifecycle evidence.
type Status string

const (
	StatusOnline  Status = "online"
	StatusOffline Status = "offline"
)

// Service is a (protocol, port) observed on the asset, with optional name and
// version banners captured at L7 (HTTP Server, SSH banner, TLS ALPN, ...).
type Service struct {
	Protocol string // "tcp" or "udp"
	Port     uint16
	Name     string // optional: "http", "ssh", ...
	Version  string // optional: "nginx 1.25", "OpenSSH 9.6", ...
}

// Asset is a single network device discovered passively.
//
// The merge pipeline guarantees:
//   - MACs, IPv4s, IPv6s, Hostnames, Services are deduplicated;
//   - FirstSeen is the earliest observed timestamp;
//   - LastSeen is the latest observed timestamp;
//   - Extra entries: scalars keep the first non-empty value, slices append.
//     Callers that need different semantics should encode the value themselves
//     (e.g. JSON-stringify a list before storing).
type Asset struct {
	ID AssetID

	// Core identifiers (canonical, dedup'd).
	MACs  []net.HardwareAddr
	IPv4s []net.IP
	IPv6s []net.IP

	// Optional typed attributes.
	Hostnames []string
	Services  []Service
	MACVendor string // best-known vendor for the primary MAC
	OS        string // best-guess OS / firmware

	// Free-form extras. May be nil. Anything that doesn't fit the typed
	// fields above: "device_type", "model", "fqdn", "dhcp_fingerprint",
	// "snmp_sysdescr", "tags", ... Keys are owned by the producers.
	Extra map[string]any

	// Lifecycle.
	FirstSeen time.Time
	LastSeen  time.Time
	Status    Status
}
package asset_test

import (
	"context"
	"testing"
	"time"

	"passivediscovery/internal/asset"
)

// Merge tests exercise mergeObservation indirectly through Manager.Apply.
//
// Covered scenarios:
//   1. New IPv4 added to asset
//   2. Existing IPv4 LastSeen updated (not overwritten)
//   3. Longer IPv4 lease replaces shorter
//   4. New hostname added (cross-source merge)
//   5. Duplicate hostname deduplicated
//   6. New service added (Protocol+Port+IsClient key)
//   7. Same service deduplicated
//   8. Same port, different IsClient → 2 entries
//   9. Scalar fields (OS, Model, DeviceType) first-wins
//  10. Extra map merges (new keys added, scalar first-wins)
//  11. SeenCount increments on each Apply
//  12. FirstSeen/LastSeen bracket correctly

func TestMerge_NewIPv4Added(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:01")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
	})

	snap := m.Snapshot()[0]
	if _, ok := snap.IPv4s["10.0.0.1"]; !ok {
		t.Error("expected IPv4 10.0.0.1 to be present")
	}
}

func TestMerge_ExistingIPv4LastSeenUpdated(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:02")
	now := time.Now()
	later := now.Add(time.Minute)

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.2": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
	})
	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: later,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.2": {FirstSeen: later, LastSeen: later, IsActive: true},
		},
	})

	snap := m.Snapshot()[0]
	if snap.IPv4s["10.0.0.2"].LastSeen != later {
		t.Errorf("expected LastSeen=%v, got %v", later, snap.IPv4s["10.0.0.2"].LastSeen)
	}
}

func TestMerge_IPv4LeaseExtended(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:03")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.3": {FirstSeen: now, LastSeen: now, Lease: time.Hour, IsActive: true},
		},
	})
	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.3": {FirstSeen: now, LastSeen: now, Lease: 2 * time.Hour, IsActive: true},
		},
	})

	snap := m.Snapshot()[0]
	if got := snap.IPv4s["10.0.0.3"].Lease; got != 2*time.Hour {
		t.Errorf("expected lease=2h, got %v", got)
	}
}

func TestMerge_NewHostnameAdded(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:04")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{
		Source: asset.SourceDHCPv4, ObservedAt: now, MAC: mac,
		Hostnames: []string{"host-a"},
	})
	m.Apply(context.Background(), asset.Observation{
		Source: asset.SourceMDNS, ObservedAt: now, MAC: mac,
		Hostnames: []string{"host-b"},
	})

	snap := m.Snapshot()[0]
	if len(snap.Hostnames) != 2 {
		t.Errorf("expected 2 hostnames, got %d: %v", len(snap.Hostnames), snap.Hostnames)
	}
}

func TestMerge_DuplicateHostnameDeduped(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:05")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceDHCPv4, ObservedAt: now, MAC: mac, Hostnames: []string{"dup-host"}})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceDHCPv4, ObservedAt: now, MAC: mac, Hostnames: []string{"dup-host"}})

	snap := m.Snapshot()[0]
	if len(snap.Hostnames) != 1 {
		t.Errorf("expected 1 hostname after dedup, got %d", len(snap.Hostnames))
	}
}

func TestMerge_NewServiceAdded(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:06")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{
		Source: asset.SourceMDNS, ObservedAt: now, MAC: mac,
		Services: []asset.Service{{Protocol: "tcp", Port: 80, Name: "http"}},
	})

	snap := m.Snapshot()[0]
	if len(snap.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(snap.Services))
	}
	if snap.Services[0].Port != 80 {
		t.Errorf("expected port 80, got %d", snap.Services[0].Port)
	}
}

func TestMerge_DuplicateServiceDeduped(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:07")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceMDNS, ObservedAt: now, MAC: mac,
		Services: []asset.Service{{Protocol: "tcp", Port: 80, Name: "http"}}})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceMDNS, ObservedAt: now, MAC: mac,
		Services: []asset.Service{{Protocol: "tcp", Port: 80, Name: "http"}}})

	snap := m.Snapshot()[0]
	if len(snap.Services) != 1 {
		t.Errorf("expected 1 service after dedup, got %d", len(snap.Services))
	}
}

func TestMerge_SamePortDifferentIsClient(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:08")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceMDNS, ObservedAt: now, MAC: mac,
		Services: []asset.Service{{Protocol: "tcp", Port: 443, Name: "https", IsClient: false}}})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceEthernet, ObservedAt: now, MAC: mac,
		Services: []asset.Service{{Protocol: "tcp", Port: 443, Name: "https", IsClient: true}}})

	snap := m.Snapshot()[0]
	if len(snap.Services) != 2 {
		t.Errorf("expected 2 services (server+client), got %d", len(snap.Services))
	}
}

func TestMerge_ScalarFirstWins(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:09")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceDHCPv4, ObservedAt: now, MAC: mac,
		OS: "Linux", DeviceType: "server", Model: "RPi"})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceSSDP, ObservedAt: now, MAC: mac,
		OS: "Windows", DeviceType: "workstation", Model: "Surface"})

	snap := m.Snapshot()[0]
	if snap.OS != "Linux" {
		t.Errorf("expected first-wins OS=Linux, got %q", snap.OS)
	}
	if snap.DeviceType != "server" {
		t.Errorf("expected first-wins DeviceType=server, got %q", snap.DeviceType)
	}
	if snap.Model != "RPi" {
		t.Errorf("expected first-wins Model=RPi, got %q", snap.Model)
	}
}

func TestMerge_ExtrasMerge(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0a")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: now, MAC: mac,
		Extra: map[string]any{"arp_operation": "request"}})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: now, MAC: mac,
		Extra: map[string]any{"arp_mac_randomized": true}})

	snap := m.Snapshot()[0]
	if snap.Extra["arp_operation"] != "request" {
		t.Error("expected arp_operation to persist")
	}
	if snap.Extra["arp_mac_randomized"] != true {
		t.Error("expected arp_mac_randomized to be added")
	}
}

func TestMerge_SeenCountIncrements(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0b")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: now, MAC: mac})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: now, MAC: mac})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: now, MAC: mac})

	snap := m.Snapshot()[0]
	if snap.SeenCount != 3 {
		t.Errorf("expected SeenCount=3, got %d", snap.SeenCount)
	}
}

func TestMerge_FirstAndLastSeenCorrect(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0c")
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: t1, MAC: mac})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: t2, MAC: mac})

	snap := m.Snapshot()[0]
	if snap.FirstSeen != t1 {
		t.Errorf("expected FirstSeen=%v, got %v", t1, snap.FirstSeen)
	}
	if snap.LastSeen != t2 {
		t.Errorf("expected LastSeen=%v, got %v", t2, snap.LastSeen)
	}
}

// mustMAC is defined in manager_test.go (same package).
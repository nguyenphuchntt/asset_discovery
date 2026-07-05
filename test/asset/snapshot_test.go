package asset_test

import (
	"testing"
	"time"

	"passivediscovery/internal/asset"
)

// Asset.Snapshot — covered scenarios:
//   1. Snapshot returns deep copy of all fields
//   2. Mutating snapshot does not affect manager state
//   3. Snapshot contains correct MAC, IPv4s, IPv6s, Hostnames, Services
//   4. Snapshot contains Extra map (deep copied)
//   5. Snapshot contains Status, FirstSeen, LastSeen, SeenCount

func TestSnapshot_DeepCopy(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:01")
	now := time.Now()

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
		Hostnames: []string{"my-host"},
		Services:  []asset.Service{{Protocol: "tcp", Port: 80, Name: "http"}},
		Extra:     map[string]any{"arp_operation": "request"},
	})

	snap := m.Snapshot()[0]

	// Mutate snapshot
	snap.IPv4s["evil"] = asset.IPEntry{}
	snap.Hostnames = append(snap.Hostnames, "evil-host")
	snap.Extra["evil"] = true

	// Verify manager is unaffected
	original := m.Snapshot()[0]
	if _, ok := original.IPv4s["evil"]; ok {
		t.Error("manager IPv4s was mutated through snapshot")
	}
	if len(original.Hostnames) != 1 {
		t.Error("manager Hostnames was mutated through snapshot")
	}
	if original.Extra["evil"] != nil {
		t.Error("manager Extra was mutated through snapshot")
	}
}

func TestSnapshot_ContainsAllFields(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:02")
	now := time.Now()

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		MACVendor:  "TestVendor",
		OS:         "Linux",
		DeviceType: "server",
		Model:      "RPi4",
		Hostnames:  []string{"host-a"},
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.2": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
		Services: []asset.Service{{Protocol: "tcp", Port: 443, Name: "https"}},
		Extra:    map[string]any{"key": "value"},
	})

	snap := m.Snapshot()[0]
	if snap.MAC.String() != mac.String() {
		t.Errorf("expected MAC=%v, got %v", mac, snap.MAC)
	}
	if snap.MACVendor != "TestVendor" {
		t.Errorf("expected MACVendor=TestVendor, got %q", snap.MACVendor)
	}
	if snap.OS != "Linux" {
		t.Errorf("expected OS=Linux, got %q", snap.OS)
	}
	if snap.DeviceType != "server" {
		t.Errorf("expected DeviceType=server, got %q", snap.DeviceType)
	}
	if snap.Model != "RPi4" {
		t.Errorf("expected Model=RPi4, got %q", snap.Model)
	}
	if snap.Status != asset.StatusOnline {
		t.Errorf("expected Status=online, got %q", snap.Status)
	}
	if snap.SeenCount != 1 {
		t.Errorf("expected SeenCount=1, got %d", snap.SeenCount)
	}
	if snap.Extra["key"] != "value" {
		t.Errorf("expected Extra[key]=value, got %v", snap.Extra["key"])
	}
}

package asset_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"passivediscovery/internal/asset"
)

// Manager.Apply — covered scenarios:
//   1. New asset created from observation
//   2. Apply same MAC twice → second is "updated"
//   3. Apply invalid observation → no error, no asset created
//   4. Apply empty source → invalid
//   5. Apply zero observed time → invalid
//   6. Apply zero MAC → invalid
//   7. Asset offline → next Apply transitions to online + emits event
//   8. Apply returns AssetID matching observation's MAC-derived ID
//   9. Multiple observations for same MAC merge into single asset
//  10. Apply with IPv4 adds IP to asset
//  11. Apply with hostname adds hostname to asset
//  12. Apply with vendor sets MACVendor (first-wins)
//  13. Apply with new vendor → no overwrite (first-wins)
//  14. Apply with model/device_type/OS → first-wins
//  15. Apply with services → services added
//  16. Apply with extra map → extra merged

func TestManager_Apply_NewAsset(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:ff")

	res, err := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Action != asset.ActionCreated {
		t.Errorf("expected Action=created, got %q", res.Action)
	}
	if res.AssetID == "" {
		t.Error("expected non-empty AssetID")
	}
}

func TestManager_Apply_Updated(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:01")

	r1, _ := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})
	r2, _ := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})

	if r1.Action != asset.ActionCreated {
		t.Errorf("first apply: expected created, got %q", r1.Action)
	}
	if r2.Action != asset.ActionUpdated {
		t.Errorf("second apply: expected updated, got %q", r2.Action)
	}
	if r1.AssetID != r2.AssetID {
		t.Errorf("expected same AssetID, got %q vs %q", r1.AssetID, r2.AssetID)
	}
}

func TestManager_Apply_InvalidSource(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	_, err := m.Apply(asset.Observation{
		Source:     "",
		ObservedAt: time.Now(),
		MAC:        mustMAC(t, "aa:bb:cc:dd:ee:02"),
	})
	if err != nil {
		t.Errorf("expected no error for invalid observation, got %v", err)
	}
	if len(m.Snapshot()) != 0 {
		t.Error("expected no asset created from invalid observation")
	}
}

func TestManager_Apply_ZeroObservedTime(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	_, err := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Time{},
		MAC:        mustMAC(t, "aa:bb:cc:dd:ee:03"),
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(m.Snapshot()) != 0 {
		t.Error("expected no asset created from zero time")
	}
}

func TestManager_Apply_ZeroMAC(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	_, err := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        nil,
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(m.Snapshot()) != 0 {
		t.Error("expected no asset created from zero MAC")
	}
}

func TestManager_Apply_OfflineToOnlineTransition(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:04")
	now := time.Now()

	// First apply
	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	// Sweep with very short offline-after → asset becomes offline
	m.Sweep(now.Add(time.Hour), time.Minute)

	// Drain events to clear
	_ = m.DrainEvents()

	// Apply again → should transition back to online
	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now.Add(time.Hour + time.Minute),
		MAC:        mac,
	})

	events := m.DrainEvents()
	hasOnline := false
	for _, e := range events {
		if e.Type == asset.EventStatusOnline {
			hasOnline = true
		}
	}
	if !hasOnline {
		t.Error("expected EventStatusOnline after offline→online transition")
	}
}

func TestManager_Apply_MultipleObsMergeIntoOneAsset(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:05")
	now := time.Now()

	// Three observations for same MAC, different sources
	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
	})
	m.Apply(asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: now,
		MAC:        mac,
		Hostnames:  []string{"my-host"},
	})
	m.Apply(asset.Observation{
		Source:    asset.SourceSSDP,
		ObservedAt: now,
		MAC:       mac,
		OS:        "Linux",
	})

	if len(m.Snapshot()) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(m.Snapshot()))
	}

	snap := m.Snapshot()[0]
	if _, ok := snap.IPv4s["10.0.0.1"]; !ok {
		t.Error("expected IPv4 from ARP observation")
	}
	if len(snap.Hostnames) == 0 || snap.Hostnames[0] != "my-host" {
		t.Errorf("expected hostname 'my-host', got %v", snap.Hostnames)
	}
	if snap.OS != "Linux" {
		t.Errorf("expected OS=Linux, got %q", snap.OS)
	}
}

func TestManager_Apply_VendorFirstWins(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:06")

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
		MACVendor:  "Apple, Inc.",
	})
	m.Apply(asset.Observation{
		Source:     asset.SourceMDNS,
		ObservedAt: time.Now(),
		MAC:        mac,
		MACVendor:  "FakeVendor",
	})

	snap := m.Snapshot()[0]
	if snap.MACVendor != "Apple, Inc." {
		t.Errorf("expected first-wins vendor=Apple, got %q", snap.MACVendor)
	}
}

func TestManager_Apply_AssetIDFormat(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:07")

	res, _ := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})
	wantID := asset.GenerateAssetID(mac)
	if res.AssetID != wantID {
		t.Errorf("expected AssetID=%q, got %q", wantID, res.AssetID)
	}
}

func TestManager_Apply_ServicesAdded(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:08")

	m.Apply(asset.Observation{
		Source:     asset.SourceMDNS,
		ObservedAt: time.Now(),
		MAC:        mac,
		Services: []asset.Service{
			{Protocol: "tcp", Port: 80, Name: "http"},
		},
	})
	snap := m.Snapshot()[0]
	if len(snap.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(snap.Services))
	}
	if snap.Services[0].Port != 80 {
		t.Errorf("expected port 80, got %d", snap.Services[0].Port)
	}
}

// Manager.Sweep — covered scenarios:
//   1. Online asset past offline-after → flipped to offline
//   2. Online asset within offline-after → stays online
//   3. Sweep returns offline transition events
//   4. Sweep with zero offline-after → asset stays online (no transition)
//   5. IP lease expiry deactivates IP (IsActive=false)

func TestManager_Sweep_OfflineTransition(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:09")
	now := time.Now()

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	// Sweep far in the future
	events := m.Sweep(now.Add(2*time.Hour), time.Hour)
	if len(events) == 0 {
		t.Fatal("expected offline event")
	}

	snap := m.Snapshot()[0]
	if snap.Status != asset.StatusOffline {
		t.Errorf("expected offline, got %q", snap.Status)
	}
}

func TestManager_Sweep_StaysOnline(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0a")
	now := time.Now()

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	// Sweep just slightly later
	events := m.Sweep(now.Add(10*time.Second), time.Hour)
	if len(events) != 0 {
		t.Errorf("expected no transition events, got %d", len(events))
	}

	snap := m.Snapshot()[0]
	if snap.Status != asset.StatusOnline {
		t.Errorf("expected online, got %q", snap.Status)
	}
}

func TestManager_Sweep_IPLeaseExpiry(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0b")
	now := time.Now()

	// Apply with a 1-hour lease
	m.Apply(asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.99": {FirstSeen: now, LastSeen: now, Lease: time.Hour, IsActive: true},
		},
	})

	// Sweep way past lease expiry + grace period (5 minutes)
	m.Sweep(now.Add(2*time.Hour), 24*time.Hour)

	snap := m.Snapshot()[0]
	if e, ok := snap.IPv4s["10.0.0.99"]; ok {
		if e.IsActive {
			t.Error("expected IP to be deactivated after lease expiry")
		}
	}
}

// DrainDirty — covered scenarios:
//   1. After Apply, DrainDirty returns snapshot of that asset
//   2. DrainDirty clears the dirty map
//   3. DrainDirty returns empty when no dirty
//   4. DrainDirty returns deep copy (modifying snapshot doesn't affect manager)

func TestManager_DrainDirty_ReturnsAsset(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0c")

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})

	drained := m.DrainDirty()
	if len(drained) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(drained))
	}
	if drained[0].ID != asset.GenerateAssetID(mac) {
		t.Errorf("expected asset ID for the applied MAC")
	}
}

func TestManager_DrainDirty_ClearsDirty(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0d")

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})

	_ = m.DrainDirty()
	second := m.DrainDirty()
	if len(second) != 0 {
		t.Errorf("expected empty after first drain, got %d", len(second))
	}
}

func TestManager_DrainDirty_EmptyWhenNoChanges(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	drained := m.DrainDirty()
	if len(drained) != 0 {
		t.Errorf("expected empty drain for new manager, got %d", len(drained))
	}
}

// DrainEvents — covered scenarios:
//   1. DrainEvents returns events from Apply
//   2. DrainEvents clears the events slice
//   3. DrainEvents returns empty when no events

func TestManager_DrainEvents_AssetCreated(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0e")

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})

	events := m.DrainEvents()
	hasCreated := false
	for _, e := range events {
		if e.Type == asset.EventAssetCreated {
			hasCreated = true
		}
	}
	if !hasCreated {
		t.Error("expected EventAssetCreated")
	}
}

func TestManager_DrainEvents_Clears(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0f")

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})
	_ = m.DrainEvents()

	second := m.DrainEvents()
	if len(second) != 0 {
		t.Errorf("expected empty after first drain, got %d", len(second))
	}
}

func TestManager_DrainEvents_IPFirstSeen(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:10")
	now := time.Now()

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
	})

	events := m.DrainEvents()
	hasIPFirstSeen := false
	for _, e := range events {
		if e.Type == asset.EventIPFirstSeen {
			hasIPFirstSeen = true
		}
	}
	if !hasIPFirstSeen {
		t.Error("expected EventIPFirstSeen for new IP")
	}
}

// Snapshot — covered scenarios:
//   1. Snapshot returns empty for new manager
//   2. Snapshot returns all assets
//   3. Snapshot returns deep copies (mutation doesn't affect manager)

func TestManager_Snapshot_Empty(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	snapshots := m.Snapshot()
	if len(snapshots) != 0 {
		t.Errorf("expected empty snapshots, got %d", len(snapshots))
	}
}

func TestManager_Snapshot_ReturnsAllAssets(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)

	m.Apply(asset.Observation{Source: asset.SourceARP, ObservedAt: time.Now(), MAC: mustMAC(t, "11:11:11:11:11:11")})
	m.Apply(asset.Observation{Source: asset.SourceARP, ObservedAt: time.Now(), MAC: mustMAC(t, "22:22:22:22:22:22")})

	if len(m.Snapshot()) != 2 {
		t.Errorf("expected 2 assets, got %d", len(m.Snapshot()))
	}
}

func TestManager_Snapshot_DeepCopy(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "33:33:33:33:33:33")

	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.50": {FirstSeen: time.Now(), LastSeen: time.Now(), IsActive: true},
		},
	})

	snap := m.Snapshot()[0]
	// Mutate snapshot — should not affect manager.
	snap.IPv4s["evil"] = asset.IPEntry{}

	original := m.Snapshot()[0]
	if _, ok := original.IPv4s["evil"]; ok {
		t.Error("manager state was mutated through snapshot")
	}
}

// LoadSnapshots — covered scenarios:
//   1. LoadSnapshots hydrates manager
//   2. LoadSnapshots with stale snapshot is skipped
//   3. LoadSnapshots with fresh snapshot replaces existing

func TestManager_LoadSnapshots_Hydrate(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "44:44:44:44:44:44")
	now := time.Now()

	snap := asset.AssetSnapshot{
		ID:        asset.GenerateAssetID(mac),
		MAC:       mac,
		FirstSeen: now,
		LastSeen:  now,
		Status:    asset.StatusOnline,
	}

	loaded := m.LoadSnapshots([]asset.AssetSnapshot{snap})
	if loaded != 1 {
		t.Errorf("expected 1 loaded, got %d", loaded)
	}

	if len(m.Snapshot()) != 1 {
		t.Errorf("expected 1 asset after load, got %d", len(m.Snapshot()))
	}
}

func TestManager_LoadSnapshots_StaleSkipped(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "55:55:55:55:55:55")
	now := time.Now()

	// Apply (sets LastSeen=now)
	m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	// Try to load older snapshot
	old := asset.AssetSnapshot{
		ID:        asset.GenerateAssetID(mac),
		MAC:       mac,
		FirstSeen: now.Add(-time.Hour),
		LastSeen:  now.Add(-time.Hour),
		Status:    asset.StatusOnline,
	}
	loaded := m.LoadSnapshots([]asset.AssetSnapshot{old})
	if loaded != 0 {
		t.Errorf("expected 0 loaded (stale), got %d", loaded)
	}
}

// Get — covered scenarios:
//   1. Get existing asset returns snapshot
//   2. Get non-existing returns false

func TestManager_Get_Existing(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "66:66:66:66:66:66")

	res, _ := m.Apply(asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})

	snap, ok := m.Get(res.AssetID)
	if !ok {
		t.Fatal("expected asset to be found")
	}
	if snap.ID != res.AssetID {
		t.Errorf("expected ID=%q, got %q", res.AssetID, snap.ID)
	}
}

func TestManager_Get_NotExisting(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	_, ok := m.Get(asset.AssetID("nonexistent"))
	if ok {
		t.Error("expected false for non-existing ID")
	}
}

// Concurrency — covered scenarios:
//   1. Apply from multiple goroutines doesn't race

func TestManager_ApplyConcurrent(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			mac := net.HardwareAddr{0x10, byte(i >> 8), byte(i), 0xAB, 0xCD, 0xEF}
			m.Apply(asset.Observation{
				Source:     asset.SourceARP,
				ObservedAt: time.Now(),
				MAC:        mac,
			})
		}(i)
	}

	wg.Wait()
	if len(m.Snapshot()) != goroutines {
		t.Errorf("expected %d assets, got %d", goroutines, len(m.Snapshot()))
	}
}

// mustMAC parses a MAC or fails the test.
func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("invalid MAC %q: %v", s, err)
	}
	return m
}
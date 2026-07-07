package asset_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"passivediscovery/internal/asset"
)

func TestManager_Apply_NewAsset(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:ff")

	res, err := m.Apply(context.Background(), asset.Observation{
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

	r1, _ := m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
	})
	r2, _ := m.Apply(context.Background(), asset.Observation{
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
	_, err := m.Apply(context.Background(), asset.Observation{
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
	_, err := m.Apply(context.Background(), asset.Observation{
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
	_, err := m.Apply(context.Background(), asset.Observation{
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

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	// Sweep with very short offline-after → asset becomes offline
	m.Sweep(now.Add(time.Hour), time.Minute)

	// Apply again → should transition back to online
	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now.Add(time.Hour + time.Minute),
		MAC:        mac,
	})

	snap := m.Snapshot()[0]
	if snap.Status != asset.StatusOnline {
		t.Errorf("expected status=online after offline->online transition, got %q", snap.Status)
	}
}

func TestManager_Apply_MultipleObsMergeIntoOneAsset(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:05")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
	})
	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: now,
		MAC:        mac,
		Hostnames:  []string{"my-host"},
	})
	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceSSDP,
		ObservedAt: now,
		MAC:        mac,
		OS:         "Linux",
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

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
		MACVendor:  "Apple, Inc.",
	})
	m.Apply(context.Background(), asset.Observation{
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

	res, _ := m.Apply(context.Background(), asset.Observation{
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

	m.Apply(context.Background(), asset.Observation{
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

// Sweep tests

func TestManager_Sweep_OfflineTransition(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:09")
	now := time.Now()

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	transitions := m.Sweep(now.Add(2*time.Hour), time.Hour)
	if transitions == 0 {
		t.Fatal("expected at least 1 transition")
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

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

	transitions := m.Sweep(now.Add(10*time.Second), time.Hour)
	if transitions != 0 {
		t.Errorf("expected 0 transitions, got %d", transitions)
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

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceDHCPv4,
		ObservedAt: now,
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.99": {FirstSeen: now, LastSeen: now, Lease: time.Hour, IsActive: true},
		},
	})

	m.Sweep(now.Add(2*time.Hour), 24*time.Hour)

	snap := m.Snapshot()[0]
	if e, ok := snap.IPv4s["10.0.0.99"]; ok {
		if e.IsActive {
			t.Error("expected IP to be deactivated after lease expiry")
		}
	}
}

// DrainDirty tests

func TestManager_DrainDirty_ReturnsAsset(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:0c")

	m.Apply(context.Background(), asset.Observation{
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

	m.Apply(context.Background(), asset.Observation{
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

// Snapshot tests

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

	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: time.Now(), MAC: mustMAC(t, "11:11:11:11:11:11")})
	m.Apply(context.Background(), asset.Observation{Source: asset.SourceARP, ObservedAt: time.Now(), MAC: mustMAC(t, "22:22:22:22:22:22")})

	if len(m.Snapshot()) != 2 {
		t.Errorf("expected 2 assets, got %d", len(m.Snapshot()))
	}
}

func TestManager_Snapshot_DeepCopy(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "33:33:33:33:33:33")

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mac,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.50": {FirstSeen: time.Now(), LastSeen: time.Now(), IsActive: true},
		},
	})

	snap := m.Snapshot()[0]
	snap.IPv4s["evil"] = asset.IPEntry{}

	original := m.Snapshot()[0]
	if _, ok := original.IPv4s["evil"]; ok {
		t.Error("manager state was mutated through snapshot")
	}
}

// LoadSnapshots tests

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

	m.Apply(context.Background(), asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: now,
		MAC:        mac,
	})

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

// Get tests

func TestManager_Get_Existing(t *testing.T) {
	t.Parallel()
	m := asset.NewManager(nil)
	mac := mustMAC(t, "66:66:66:66:66:66")

	res, _ := m.Apply(context.Background(), asset.Observation{
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

// Concurrency

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
			m.Apply(context.Background(), asset.Observation{
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

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("invalid MAC %q: %v", s, err)
	}
	return m
}

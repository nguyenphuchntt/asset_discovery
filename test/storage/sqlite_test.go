package storage_test

import (
	"context"
	"net"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/storage"
)

func newRepo(t *testing.T) (storage.Repository, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	repo, err := storage.OpenSQLite(storage.SQLiteOptions{
		Path:        dir + "/test.db",
		WAL:         true,
		BusyTimeout: 5 * time.Second,
	})
	if err != nil {
		cancel()
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := repo.Init(ctx); err != nil {
		cancel()
		repo.Close()
		t.Fatalf("failed to init schema: %v", err)
	}
	return repo, cancel
}

func TestSQLite_OpenAndInit(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	if repo == nil {
		t.Fatal("expected non-nil repo")
	}
}

func TestSQLite_InitIdempotent(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	if err := repo.Init(ctx); err != nil {
		t.Fatalf("second Init should not fail: %v", err)
	}
}

func TestSQLite_SaveBatchAndLoadAssets(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	snap := asset.AssetSnapshot{
		ID:         "mac:aa:bb:cc:dd:ee:01",
		MAC:        mustMAC(t, "aa:bb:cc:dd:ee:01"),
		Status:     asset.StatusOnline,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: now, LastSeen: now, Lease: time.Hour, IsActive: true},
		},
		Hostnames:  []string{"test-host"},
		Services:   []asset.Service{{Protocol: "tcp", Port: 80, Name: "http", IsActive: true, LastSeen: now}},
		MACVendor:  "TestVendor",
		OS:         "Linux",
		DeviceType: "server",
		Model:      "RPi",
		Extra:      map[string]any{"key": "value"},
		FirstSeen:  now,
		LastSeen:   now,
		SeenCount:  10,
	}

	err := repo.SaveBatch(ctx, storage.Batch{
		RunID:  "run_001",
		Assets: []asset.AssetSnapshot{snap},
	})
	if err != nil {
		t.Fatalf("SaveBatch failed: %v", err)
	}

	loaded, err := repo.LoadAssets(ctx, storage.LoadOptions{})
	if err != nil {
		t.Fatalf("LoadAssets failed: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(loaded))
	}

	l := loaded[0]
	if l.ID != snap.ID {
		t.Errorf("expected ID=%q, got %q", snap.ID, l.ID)
	}
	if l.OS != "Linux" {
		t.Errorf("expected OS=Linux, got %q", l.OS)
	}
	if l.DeviceType != "server" {
		t.Errorf("expected DeviceType=server, got %q", l.DeviceType)
	}
	if l.Model != "RPi" {
		t.Errorf("expected Model=RPi, got %q", l.Model)
	}
	if l.MACVendor != "TestVendor" {
		t.Errorf("expected MACVendor=TestVendor, got %q", l.MACVendor)
	}
	if l.SeenCount != 10 {
		t.Errorf("expected SeenCount=10, got %d", l.SeenCount)
	}
	if len(l.Hostnames) != 1 || l.Hostnames[0] != "test-host" {
		t.Errorf("expected hostname test-host, got %v", l.Hostnames)
	}
}

func TestSQLite_ChildRowsIPs(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	snap := asset.AssetSnapshot{
		ID:     "mac:aa:bb:cc:dd:ee:02",
		MAC:    mustMAC(t, "aa:bb:cc:dd:ee:02"),
		Status: asset.StatusOnline,
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.2":     {FirstSeen: now, LastSeen: now, IsActive: true},
			"192.168.1.10": {FirstSeen: now, LastSeen: now, IsActive: true},
		},
		FirstSeen: now,
		LastSeen:  now,
	}

	repo.SaveBatch(ctx, storage.Batch{RunID: "r1", Assets: []asset.AssetSnapshot{snap}})
	loaded, _ := repo.LoadAssets(ctx, storage.LoadOptions{})

	if len(loaded[0].IPv4s) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(loaded[0].IPv4s))
	}
}

func TestSQLite_ChildRowsHostnames(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	snap1 := asset.AssetSnapshot{
		ID: "mac:aa:bb:cc:dd:ee:03", MAC: mustMAC(t, "aa:bb:cc:dd:ee:03"),
		Status: asset.StatusOnline, Hostnames: []string{"host-a"}, FirstSeen: now, LastSeen: now,
	}
	repo.SaveBatch(ctx, storage.Batch{RunID: "r1", Assets: []asset.AssetSnapshot{snap1}})

	snap2 := snap1
	snap2.Hostnames = []string{"host-b", "host-c"}
	repo.SaveBatch(ctx, storage.Batch{RunID: "r2", Assets: []asset.AssetSnapshot{snap2}})

	loaded, _ := repo.LoadAssets(ctx, storage.LoadOptions{})
	wantHostnames := map[string]bool{"host-a": true, "host-b": true, "host-c": true}
	if len(loaded[0].Hostnames) != 3 {
		t.Errorf("expected 3 hostnames after merge, got %d: %v", len(loaded[0].Hostnames), loaded[0].Hostnames)
	}
	for _, h := range loaded[0].Hostnames {
		if !wantHostnames[h] {
			t.Errorf("unexpected hostname %q", h)
		}
	}
}

func TestSQLite_ChildRowsServices(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	snap := asset.AssetSnapshot{
		ID: "mac:aa:bb:cc:dd:ee:04", MAC: mustMAC(t, "aa:bb:cc:dd:ee:04"),
		Status: asset.StatusOnline, FirstSeen: now, LastSeen: now,
		Services: []asset.Service{
			{Protocol: "tcp", Port: 80, Name: "http", IsActive: true, LastSeen: now},
			{Protocol: "tcp", Port: 443, Name: "https", IsActive: true, LastSeen: now},
		},
	}
	repo.SaveBatch(ctx, storage.Batch{RunID: "r1", Assets: []asset.AssetSnapshot{snap}})
	loaded, _ := repo.LoadAssets(ctx, storage.LoadOptions{})

	if len(loaded[0].Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(loaded[0].Services))
	}
}

func TestSQLite_EmptyBatchNoop(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	err := repo.SaveBatch(context.Background(), storage.Batch{})
	if err != nil {
		t.Fatalf("empty batch should not error: %v", err)
	}
}

func TestSQLite_UpsertCOALESCE(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	snap := asset.AssetSnapshot{
		ID: "mac:aa:bb:cc:dd:ee:05", MAC: mustMAC(t, "aa:bb:cc:dd:ee:05"),
		Status: asset.StatusOnline, OS: "Linux", FirstSeen: now, LastSeen: now,
	}
	repo.SaveBatch(ctx, storage.Batch{RunID: "r1", Assets: []asset.AssetSnapshot{snap}})

	snap.OS = ""
	snap.SeenCount = 1
	repo.SaveBatch(ctx, storage.Batch{RunID: "r2", Assets: []asset.AssetSnapshot{snap}})

	loaded, _ := repo.LoadAssets(ctx, storage.LoadOptions{})
	if loaded[0].OS != "Linux" {
		t.Errorf("expected COALESCE to keep Linux, got %q", loaded[0].OS)
	}
}

func TestSQLite_SaveRunRoundTrip(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	err := repo.SaveRunStart(ctx, storage.CaptureRun{
		ID: "run_002", Mode: "pcap", SourceName: "test.pcap",
		StartedAt: now, PacketsReceived: 1000,
	})
	if err != nil {
		t.Fatalf("SaveRunStart failed: %v", err)
	}

	err = repo.SaveRunEnd(ctx, storage.CaptureRun{
		ID: "run_002", EndedAt: now.Add(time.Minute),
		PacketsReceived: 1000, Observations: 50,
	})
	if err != nil {
		t.Fatalf("SaveRunEnd failed: %v", err)
	}
}

func TestSQLite_SaveStats(t *testing.T) {
	t.Parallel()
	repo, cancel := newRepo(t)
	defer cancel()
	defer repo.Close()

	ctx := context.Background()
	if err := repo.SaveRunStart(ctx, storage.CaptureRun{
		ID: "run_003", Mode: "pcap", SourceName: "test.pcap",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveRunStart failed: %v", err)
	}
	err := repo.SaveStats(ctx, storage.StatsSnapshot{
		RunID:           "run_003",
		CapturedAt:      time.Now().UTC(),
		PacketsReceived: 1000,
		Observations:    50,
		DBFlushCount:    10,
		DBFlushErrors:   1,
		DBFlushLast:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("SaveStats failed: %v", err)
	}
}

func TestSQLite_OpenEmptyPath(t *testing.T) {
	t.Parallel()
	_, err := storage.OpenSQLite(storage.SQLiteOptions{Path: ""})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("invalid MAC: %v", err)
	}
	return m
}

package storage_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/storage"
)

// openTestDB returns an in-memory SQLite repo with schema applied.
// Always call close(t) to release.
func openTestDB(t *testing.T) *storage.SQLiteRepo {
	t.Helper()
	dir := t.TempDir()
	repo, err := storage.OpenSQLite(storage.SQLiteOptions{
		Path:        filepath.Join(dir, "test.db"),
		WAL:         true,
		BusyTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	if err := repo.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return repo
}

// ---------- OpenSQLite ----------

func TestOpenSQLite_EmptyPath(t *testing.T) {
	_, err := storage.OpenSQLite(storage.SQLiteOptions{Path: ""})
	if err == nil {
		t.Error("empty path: expected error")
	}
}

func TestOpenSQLite_InvalidPath(t *testing.T) {
	_, err := storage.OpenSQLite(storage.SQLiteOptions{
		Path: "/nonexistent/dir/cannot/create.db",
	})
	if err == nil {
		t.Error("invalid path: expected error")
	}
}

func TestOpenSQLite_ValidPath(t *testing.T) {
	dir := t.TempDir()
	repo, err := storage.OpenSQLite(storage.SQLiteOptions{
		Path:        filepath.Join(dir, "test.db"),
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	repo.Close()
}

// ---------- Init ----------

func TestInit_Idempotent(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	// Calling Init twice should not error
	if err := repo.Init(context.Background()); err != nil {
		t.Errorf("Init second call: %v", err)
	}
}

// ---------- SaveBatch / LoadAssets ----------

func TestSaveBatch_Empty(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	if err := repo.SaveBatch(context.Background(), nil); err != nil {
		t.Errorf("SaveBatch nil: %v", err)
	}
	if err := repo.SaveBatch(context.Background(), []asset.AssetSnapshot{}); err != nil {
		t.Errorf("SaveBatch empty: %v", err)
	}
}

func TestSaveBatch_InsertAndLoad(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	now := time.Now().UTC()
	assets := []asset.AssetSnapshot{
		{
			ID:        "mac:aa:bb:cc:dd:ee:01",
			MAC:       mustMAC(t, "aa:bb:cc:dd:ee:01"),
			Status:    asset.StatusOnline,
			IPv4s:     map[string]asset.IPEntry{"10.0.0.1": {FirstSeen: now, LastSeen: now, IsActive: true}},
			Hostnames: []string{"device1"},
			Services:  []asset.Service{{Protocol: "tcp", Port: 80, Name: "http", LastSeen: now}},
			FirstSeen: now,
			LastSeen:  now,
			SeenCount: 1,
		},
	}
	if err := repo.SaveBatch(context.Background(), assets); err != nil {
		t.Fatalf("SaveBatch: %v", err)
	}

	loaded, err := repo.LoadAssets(context.Background(), storage.LoadOptions{})
	if err != nil {
		t.Fatalf("LoadAssets: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("LoadAssets count: want 1, got %d", len(loaded))
	}
	got := loaded[0]
	if got.ID != assets[0].ID {
		t.Errorf("ID: want %s, got %s", assets[0].ID, got.ID)
	}
	if len(got.IPv4s) != 1 {
		t.Errorf("IPv4s len: want 1, got %d", len(got.IPv4s))
	}
	if len(got.Hostnames) != 1 {
		t.Errorf("Hostnames len: want 1, got %d", len(got.Hostnames))
	}
	if len(got.Services) != 1 {
		t.Errorf("Services len: want 1, got %d", len(got.Services))
	}
}

func TestSaveBatch_UpdateExisting(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	now := time.Now().UTC()
	a := asset.AssetSnapshot{
		ID:        "mac:aa:bb:cc:dd:ee:01",
		MAC:       mustMAC(t, "aa:bb:cc:dd:ee:01"),
		Status:    asset.StatusOnline,
		FirstSeen: now,
		LastSeen:  now,
	}

	// First save
	if err := repo.SaveBatch(context.Background(), []asset.AssetSnapshot{a}); err != nil {
		t.Fatalf("SaveBatch 1: %v", err)
	}

	// Update with newer LastSeen
	a.LastSeen = now.Add(time.Hour)
	a.SeenCount = 5
	if err := repo.SaveBatch(context.Background(), []asset.AssetSnapshot{a}); err != nil {
		t.Fatalf("SaveBatch 2: %v", err)
	}

	loaded, _ := repo.LoadAssets(context.Background(), storage.LoadOptions{})
	if len(loaded) != 1 {
		t.Fatalf("count: want 1, got %d", len(loaded))
	}
	if loaded[0].SeenCount != 5 {
		t.Errorf("SeenCount: want 5, got %d", loaded[0].SeenCount)
	}
}

func TestLoadAssets_WithSince(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	old := time.Now().Add(-2 * time.Hour).UTC()
	recent := time.Now().UTC()

	assets := []asset.AssetSnapshot{
		{ID: "mac:11:11:11:11:11:01", MAC: mustMAC(t, "11:11:11:11:11:01"), FirstSeen: old, LastSeen: old, SeenCount: 1},
		{ID: "mac:11:11:11:11:11:02", MAC: mustMAC(t, "11:11:11:11:11:02"), FirstSeen: recent, LastSeen: recent, SeenCount: 1},
	}
	repo.SaveBatch(context.Background(), assets)

	// Since = 1h ago - should only return recent
	since := time.Now().Add(-time.Hour)
	loaded, _ := repo.LoadAssets(context.Background(), storage.LoadOptions{Since: since})
	if len(loaded) != 1 {
		t.Errorf("count: want 1 (recent only), got %d", len(loaded))
	}
}

func TestLoadAssets_WithLimit(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	now := time.Now().UTC()
	assets := make([]asset.AssetSnapshot, 5)
	for i := range assets {
		assets[i] = asset.AssetSnapshot{
			ID:        asset.AssetID("mac:11:11:11:11:11:0" + string(rune('1'+i))),
			MAC:       mustMAC(t, "11:11:11:11:11:0"+string(rune('1'+i))),
			FirstSeen: now,
			LastSeen:  now,
			SeenCount: 1,
		}
	}
	repo.SaveBatch(context.Background(), assets)

	loaded, _ := repo.LoadAssets(context.Background(), storage.LoadOptions{Limit: 3})
	if len(loaded) != 3 {
		t.Errorf("Limit: want 3, got %d", len(loaded))
	}
}

// ---------- LoadAssetByMAC ----------

func TestLoadAssetByMAC_Found(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	now := time.Now().UTC()
	a := asset.AssetSnapshot{
		ID:        "mac:aa:bb:cc:dd:ee:01",
		MAC:       mustMAC(t, "aa:bb:cc:dd:ee:01"),
		FirstSeen: now,
		LastSeen:  now,
		SeenCount: 1,
	}
	repo.SaveBatch(context.Background(), []asset.AssetSnapshot{a})

	got, err := repo.LoadAssetByMAC(context.Background(), "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("LoadAssetByMAC: %v", err)
	}
	if got == nil {
		t.Fatal("got nil")
	}
	if got.ID != a.ID {
		t.Errorf("ID: want %s, got %s", a.ID, got.ID)
	}
}

func TestLoadAssetByMAC_NotFound(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	got, err := repo.LoadAssetByMAC(context.Background(), "00:00:00:00:00:99")
	if err != nil {
		t.Errorf("err: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestLoadAssetByMAC_Empty(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	got, err := repo.LoadAssetByMAC(context.Background(), "")
	if err != nil {
		t.Errorf("err: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// ---------- SaveStatistics / LoadLastStatistics ----------

func TestSaveStatistics(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	now := time.Now().UTC()
	stats := storage.Statistics{
		CapturedAt:      now,
		PacketsReceived: 100,
		AssetsCount:     5,
		PacketsPerSec:   1.5,
	}
	if err := repo.SaveStatistics(context.Background(), stats); err != nil {
		t.Fatalf("SaveStatistics: %v", err)
	}

	got, ok, err := repo.LoadLastStatistics(context.Background())
	if err != nil {
		t.Fatalf("LoadLastStatistics: %v", err)
	}
	if !ok {
		t.Fatal("ok: want true")
	}
	if got.PacketsReceived != 100 {
		t.Errorf("PacketsReceived: want 100, got %d", got.PacketsReceived)
	}
	if got.AssetsCount != 5 {
		t.Errorf("AssetsCount: want 5, got %d", got.AssetsCount)
	}
	if got.PacketsPerSec != 1.5 {
		t.Errorf("PacketsPerSec: want 1.5, got %v", got.PacketsPerSec)
	}
}

func TestLoadLastStatistics_Empty(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	got, ok, err := repo.LoadLastStatistics(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false on empty table, got %+v", got)
	}
}

func TestLoadLastStatistics_OnlyLast(t *testing.T) {
	repo := openTestDB(t)
	defer repo.Close()

	t0 := time.Now().Add(-2 * time.Hour).UTC()
	t1 := time.Now().Add(-time.Hour).UTC()
	t2 := time.Now().UTC()

	repo.SaveStatistics(context.Background(), storage.Statistics{CapturedAt: t0, PacketsReceived: 100})
	repo.SaveStatistics(context.Background(), storage.Statistics{CapturedAt: t1, PacketsReceived: 200})
	repo.SaveStatistics(context.Background(), storage.Statistics{CapturedAt: t2, PacketsReceived: 300})

	got, ok, _ := repo.LoadLastStatistics(context.Background())
	if !ok {
		t.Fatal("ok=false")
	}
	if got.PacketsReceived != 300 {
		t.Errorf("want last (300), got %d", got.PacketsReceived)
	}
}

// ---------- helper ----------

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("parse MAC: %v", err)
	}
	return m
}

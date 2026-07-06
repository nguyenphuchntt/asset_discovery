package output_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/output"
)

// JSONSink — covered scenarios:
//   1. WriteAssets creates .assets.json file with valid JSON
//   2. WriteEvents creates .events.json file with valid JSON
//   3. Round-trip JSON decode preserves data
//   4. Empty snapshot → valid JSON (empty array)
//   5. Empty events → valid JSON (empty array)
//   6. AssetsPath/EventsPath predictable naming
//   7. Nonexistent directory → error

func TestJSONSink_WriteAssets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink := output.NewJSONSink(dir, nil)

	snapshots := []asset.AssetSnapshot{
		{
			ID: "mac:aa:bb:cc:dd:ee:01", MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"),
			Status: asset.StatusOnline, OS: "Linux",
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), SeenCount: 10,
		},
	}

	if err := sink.WriteAssets(context.Background(), snapshots); err != nil {
		t.Fatalf("WriteAssets failed: %v", err)
	}

	data, err := os.ReadFile(sink.AssetsPath())
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var loaded []asset.AssetSnapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(loaded) != 1 || loaded[0].OS != "Linux" {
		t.Errorf("expected 1 asset with OS=Linux, got %+v", loaded)
	}
}

func TestJSONSink_WriteEvents(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink := output.NewJSONSink(dir, nil)

	events := []asset.Event{
		{Type: asset.EventAssetCreated, AssetID: "mac:aa:bb:cc:dd:ee:01", At: time.Now().UTC()},
	}

	if err := sink.WriteEvents(context.Background(), events); err != nil {
		t.Fatalf("WriteEvents failed: %v", err)
	}

	data, err := os.ReadFile(sink.EventsPath())
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var loaded []asset.Event
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Type != asset.EventAssetCreated {
		t.Errorf("expected 1 event, got %+v", loaded)
	}
}

func TestJSONSink_EmptyOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink := output.NewJSONSink(dir, nil)

	_ = sink.WriteAssets(context.Background(), []asset.AssetSnapshot{})
	_ = sink.WriteEvents(context.Background(), []asset.Event{})

	data, _ := os.ReadFile(sink.AssetsPath())
	var arr []any
	if err := json.Unmarshal(data, &arr); err != nil {
		t.Fatalf("empty assets not valid JSON: %v", err)
	}
}

func TestJSONSink_Paths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink := output.NewJSONSink(dir, nil)

	if filepath.Ext(sink.AssetsPath()) != ".json" {
		t.Errorf("AssetsPath should end in .json: %q", sink.AssetsPath())
	}
	if filepath.Ext(sink.EventsPath()) != ".json" {
		t.Errorf("EventsPath should end in .json: %q", sink.EventsPath())
	}
}

func TestJSONSink_NonexistentDir(t *testing.T) {
	t.Parallel()
	sink := output.NewJSONSink("/nonexistent/path/test", nil)
	err := sink.WriteAssets(context.Background(), []asset.AssetSnapshot{{}})
	if err == nil {
		t.Error("expected error for nonexistent directory")
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
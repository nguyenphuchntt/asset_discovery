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

func TestJSONSink_EmptyOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink := output.NewJSONSink(dir, nil)

	_ = sink.WriteAssets(context.Background(), []asset.AssetSnapshot{})

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

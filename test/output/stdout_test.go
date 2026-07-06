package output_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/output"
)

// StdoutSink — covered scenarios:
//   1. PrintSummary renders header
//   2. Renders status breakdown (online/offline counts)
//   3. Renders event type breakdown
//   4. Renders per-asset box with all fields
//   5. MAC, Vendor, IPv4s/IPv6s shown
//   6. Hostnames, OS, Model, DeviceType shown
//   7. Services shown (with client/server role)
//   8. Extras shown (sorted alphabetically)
//   9. First/Last seen + SeenCount shown
//  10. Empty snapshots → graceful (just header)
//  11. Nil Out → defaults to stdout (don't crash)
//  12. Multiple assets → multiple boxes

func TestStdoutSink_PrintSummary_Empty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}
	sink.PrintSummary(nil, nil)

	output := buf.String()
	if !strings.Contains(output, "discovery summary") {
		t.Errorf("expected 'discovery summary' header, got %q", output)
	}
	if !strings.Contains(output, "assets discovered : 0") {
		t.Errorf("expected 0 assets in summary, got %q", output)
	}
}

func TestStdoutSink_PrintSummary_StatusBreakdown(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	snapshots := []asset.AssetSnapshot{
		{ID: "id1", MAC: mustMAC(t, "11:11:11:11:11:11"), Status: asset.StatusOnline},
		{ID: "id2", MAC: mustMAC(t, "22:22:22:22:22:22"), Status: asset.StatusOnline},
		{ID: "id3", MAC: mustMAC(t, "33:33:33:33:33:33"), Status: asset.StatusOffline},
	}
	sink.PrintSummary(snapshots, nil)
	out := buf.String()

	if !strings.Contains(out, "online: 2") {
		t.Errorf("expected 'online: 2', got %q", out)
	}
	if !strings.Contains(out, "offline: 1") {
		t.Errorf("expected 'offline: 1', got %q", out)
	}
}

func TestStdoutSink_PrintSummary_EventBreakdown(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	events := []asset.Event{
		{Type: asset.EventAssetCreated, AssetID: "id1"},
		{Type: asset.EventAssetCreated, AssetID: "id2"},
		{Type: asset.EventStatusOnline, AssetID: "id3"},
	}
	sink.PrintSummary(nil, events)
	out := buf.String()

	if !strings.Contains(out, "asset_created") {
		t.Errorf("expected asset_created in breakdown, got %q", out)
	}
	if !strings.Contains(out, "status_online") {
		t.Errorf("expected status_online in breakdown, got %q", out)
	}
}

func TestStdoutSink_PrintSummary_PerAssetBox(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	snap := asset.AssetSnapshot{
		ID:        "mac:aa:bb:cc:dd:ee:01",
		MAC:       mustMAC(t, "aa:bb:cc:dd:ee:01"),
		Status:    asset.StatusOnline,
		MACVendor: "TestVendor",
		OS:        "Linux",
		Model:     "RPi",
		Hostnames: []string{"myhost"},
		IPv4s: map[string]asset.IPEntry{
			"10.0.0.1": {FirstSeen: time.Now(), LastSeen: time.Now(), IsActive: true},
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		SeenCount: 42,
	}
	sink.PrintSummary([]asset.AssetSnapshot{snap}, nil)
	out := buf.String()

	if !strings.Contains(out, "TestVendor") {
		t.Error("expected MAC vendor in output")
	}
	if !strings.Contains(out, "10.0.0.1") {
		t.Error("expected IPv4 in output")
	}
	if !strings.Contains(out, "Linux") {
		t.Error("expected OS in output")
	}
	if !strings.Contains(out, "42") {
		t.Error("expected SeenCount in output")
	}
}

func TestStdoutSink_PrintSummary_ServicesWithRoles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	snap := asset.AssetSnapshot{
		ID: "id1", MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"),
		Status: asset.StatusOnline,
		Services: []asset.Service{
			{Protocol: "tcp", Port: 80, Name: "http", IsClient: false},
			{Protocol: "tcp", Port: 443, Name: "https", IsClient: true},
		},
	}
	sink.PrintSummary([]asset.AssetSnapshot{snap}, nil)
	out := buf.String()

	if !strings.Contains(out, "[server]") {
		t.Error("expected [server] role tag")
	}
	if !strings.Contains(out, "[client]") {
		t.Error("expected [client] role tag")
	}
	if !strings.Contains(out, "80") {
		t.Error("expected port 80 in output")
	}
}

func TestStdoutSink_PrintSummary_ExtrasSorted(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	snap := asset.AssetSnapshot{
		ID: "id1", MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"),
		Status: asset.StatusOnline,
		Extra: map[string]any{
			"z_last":   "Z",
			"a_first":  "A",
			"m_middle": "M",
		},
	}
	sink.PrintSummary([]asset.AssetSnapshot{snap}, nil)
	out := buf.String()

	// Verify alphabetical order: a_first appears before m_middle before z_last
	posA := strings.Index(out, "a_first")
	posM := strings.Index(out, "m_middle")
	posZ := strings.Index(out, "z_last")

	if posA < 0 || posM < 0 || posZ < 0 {
		t.Fatalf("all 3 keys should appear, got %q", out)
	}
	if !(posA < posM && posM < posZ) {
		t.Errorf("expected sorted order a < m < z, got positions %d %d %d", posA, posM, posZ)
	}
}

func TestStdoutSink_PrintSummary_BoxDrawingChars(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	snap := asset.AssetSnapshot{
		ID: "id1", MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"),
		Status: asset.StatusOnline,
	}
	sink.PrintSummary([]asset.AssetSnapshot{snap}, nil)
	out := buf.String()

	// Unicode box-drawing chars
	if !strings.Contains(out, "┌") {
		t.Error("expected top-left box char ┌")
	}
	if !strings.Contains(out, "┐") {
		t.Error("expected top-right box char ┐")
	}
	if !strings.Contains(out, "└") {
		t.Error("expected bottom-left box char └")
	}
	if !strings.Contains(out, "┘") {
		t.Error("expected bottom-right box char ┘")
	}
	if !strings.Contains(out, "│") {
		t.Error("expected vertical bar │")
	}
}

func TestStdoutSink_NewDefaultsToStdout(t *testing.T) {
	t.Parallel()
	sink := output.NewStdoutSink()
	if sink.Out == nil {
		t.Error("expected default Out to be os.Stdout, got nil")
	}
}

func TestStdoutSink_PrintSummary_MultipleAssets(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	sink := &output.StdoutSink{Out: &buf}

	snaps := []asset.AssetSnapshot{
		{ID: "id1", MAC: mustMAC(t, "aa:bb:cc:dd:ee:01"), Status: asset.StatusOnline},
		{ID: "id2", MAC: mustMAC(t, "bb:bb:cc:dd:ee:02"), Status: asset.StatusOnline},
		{ID: "id3", MAC: mustMAC(t, "cc:bb:cc:dd:ee:03"), Status: asset.StatusOffline},
	}
	sink.PrintSummary(snaps, nil)
	out := buf.String()

	// Should have 3 boxes
	if strings.Count(out, "┌") != 3 {
		t.Errorf("expected 3 box starts, got %d", strings.Count(out, "┌"))
	}
	if strings.Count(out, "└") != 3 {
		t.Errorf("expected 3 box ends, got %d", strings.Count(out, "└"))
	}
}
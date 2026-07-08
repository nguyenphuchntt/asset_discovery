package asset_test

import (
	"net"
	"testing"
	"time"

	"passivediscovery/internal/asset"
)

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// ---------- NormalizeMACAddr ----------

func TestNormalizeMACAddr_Valid(t *testing.T) {
	got := asset.NormalizeMACAddr(mustMAC("aa:bb:cc:dd:ee:ff"))
	if got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("got %q, want aa:bb:cc:dd:ee:ff", got)
	}
}

func TestNormalizeMACAddr_Nil(t *testing.T) {
	if got := asset.NormalizeMACAddr(nil); got != "" {
		t.Errorf("nil MAC: want empty, got %q", got)
	}
}

// ---------- NormalizeIPv4Addr ----------

func TestNormalizeIPv4Addr_Valid(t *testing.T) {
	got := asset.NormalizeIPv4Addr(net.ParseIP("192.168.1.1"))
	if got != "192.168.1.1" {
		t.Errorf("got %q, want 192.168.1.1", got)
	}
}

func TestNormalizeIPv4Addr_Nil(t *testing.T) {
	if got := asset.NormalizeIPv4Addr(nil); got != "" {
		t.Errorf("nil: want empty, got %q", got)
	}
}

func TestNormalizeIPv4Addr_IPv6(t *testing.T) {
	if got := asset.NormalizeIPv4Addr(net.ParseIP("2001:db8::1")); got != "" {
		t.Errorf("IPv6 to IPv4: want empty, got %q", got)
	}
}

func TestNormalizeIPv4Addr_IPv4In16(t *testing.T) {
	ip := net.ParseIP("10.0.0.1").To16()
	if got := asset.NormalizeIPv4Addr(ip); got != "10.0.0.1" {
		t.Errorf("To16 IPv4: got %q, want 10.0.0.1", got)
	}
}

// ---------- NormalizeIPv6Addr ----------

func TestNormalizeIPv6Addr_Valid(t *testing.T) {
	got := asset.NormalizeIPv6Addr(net.ParseIP("2001:db8::1"))
	if got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}

func TestNormalizeIPv6Addr_LinkLocal(t *testing.T) {
	if got := asset.NormalizeIPv6Addr(net.ParseIP("fe80::1")); got != "fe80::1" {
		t.Errorf("link-local: got %q, want fe80::1", got)
	}
}

func TestNormalizeIPv6Addr_Nil(t *testing.T) {
	if got := asset.NormalizeIPv6Addr(nil); got != "" {
		t.Errorf("nil: want empty, got %q", got)
	}
}

func TestNormalizeIPv6Addr_IPv4(t *testing.T) {
	if got := asset.NormalizeIPv6Addr(net.ParseIP("192.168.1.1")); got != "" {
		t.Errorf("IPv4 to IPv6: want empty, got %q", got)
	}
}

// ---------- CloneMAC ----------

func TestCloneMAC_Valid(t *testing.T) {
	orig := mustMAC("aa:bb:cc:dd:ee:ff")
	clone := asset.CloneMAC(orig)
	if clone.String() != orig.String() {
		t.Errorf("clone %s != orig %s", clone, orig)
	}
	orig[0] = 0xff
	if clone[0] == 0xff {
		t.Error("CloneMAC: clone is not independent")
	}
}

func TestCloneMAC_Empty(t *testing.T) {
	if got := asset.CloneMAC(nil); got != nil {
		t.Errorf("empty: want nil, got %v", got)
	}
	if got := asset.CloneMAC(net.HardwareAddr{}); got != nil {
		t.Errorf("zero-len: want nil, got %v", got)
	}
}

// ---------- mergeIPMap ----------

func newEntry(last time.Time) asset.IPEntry {
	return asset.IPEntry{FirstSeen: last, LastSeen: last, IsActive: true}
}

func TestMergeIPMap_Empty(t *testing.T) {
	var dst map[string]asset.IPEntry
	changed, added := asset.MergeIPMap(&dst, nil, time.Now())
	if changed || added != nil {
		t.Errorf("empty src: got changed=%v added=%v", changed, added)
	}
}

func TestMergeIPMap_NilDst(t *testing.T) {
	var dst map[string]asset.IPEntry
	t0 := time.Now()
	changed, added := asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": newEntry(t0),
	}, t0)
	if !changed {
		t.Error("expected changed=true for nil dst")
	}
	if len(added) != 1 || added[0] != "10.0.0.1" {
		t.Errorf("added: want [10.0.0.1], got %v", added)
	}
}

func TestMergeIPMap_SkipEmptyIP(t *testing.T) {
	var dst map[string]asset.IPEntry
	changed, _ := asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"": newEntry(time.Now()),
	}, time.Now())
	if changed {
		t.Error("empty IP key should be skipped")
	}
}

func TestMergeIPMap_UpdateLastSeen(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	var dst map[string]asset.IPEntry
	asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": newEntry(t1),
	}, t0)

	changed, _ := asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": newEntry(t2),
	}, t0)
	if !changed {
		t.Error("expected changed=true on newer last_seen")
	}
	if !dst["10.0.0.1"].LastSeen.Equal(t2) {
		t.Errorf("LastSeen: want %v, got %v", t2, dst["10.0.0.1"].LastSeen)
	}
}

func TestMergeIPMap_OldLastSeenNoChange(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	var dst map[string]asset.IPEntry
	asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": newEntry(t1),
	}, t0)
	changed, _ := asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": newEntry(t0),
	}, t0)
	if changed {
		t.Error("expected changed=false for older last_seen")
	}
}

func TestMergeIPMap_UpdateLease(t *testing.T) {
	t0 := time.Now()
	var dst map[string]asset.IPEntry
	asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": {FirstSeen: t0, LastSeen: t0, Lease: time.Hour, IsActive: true},
	}, t0)
	changed, _ := asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": {FirstSeen: t0, LastSeen: t0, Lease: 2 * time.Hour, IsActive: true},
	}, t0)
	if !changed {
		t.Error("expected changed=true on longer lease")
	}
}

func TestMergeIPMap_Reactivate(t *testing.T) {
	t0 := time.Now()
	var dst map[string]asset.IPEntry
	asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": {FirstSeen: t0, LastSeen: t0, IsActive: true},
	}, t0)
	entry := dst["10.0.0.1"]
	entry.IsActive = false
	dst["10.0.0.1"] = entry

	changed, _ := asset.MergeIPMap(&dst, map[string]asset.IPEntry{
		"10.0.0.1": newEntry(t0),
	}, t0)
	if !changed {
		t.Error("expected changed=true on reactivation")
	}
	if !dst["10.0.0.1"].IsActive {
		t.Error("IsActive should be true after reactivation")
	}
}

// ---------- touchTimestamps ----------

func TestTouchTimestamps_FirstCall(t *testing.T) {
	t0 := time.Now()
	now := t0.Add(time.Hour)
	a := &asset.Asset{FirstSeen: time.Time{}, LastSeen: time.Time{}}
	changed := asset.TouchTimestamps(a, now)
	if !changed {
		t.Error("expected changed=true on first call")
	}
	if !a.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen: want %v, got %v", now, a.FirstSeen)
	}
	if !a.LastSeen.Equal(now) {
		t.Errorf("LastSeen: want %v, got %v", now, a.LastSeen)
	}
}

func TestTouchTimestamps_Zero(t *testing.T) {
	a := &asset.Asset{}
	changed := asset.TouchTimestamps(a, time.Time{})
	if changed {
		t.Error("zero time should return false")
	}
}

func TestTouchTimestamps_OlderFirstSeen(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(-time.Hour)

	a := &asset.Asset{FirstSeen: t0, LastSeen: t1}
	changed := asset.TouchTimestamps(a, t2)
	if !changed {
		t.Error("expected changed=true when at < FirstSeen")
	}
	if !a.FirstSeen.Equal(t2) {
		t.Errorf("FirstSeen: want %v, got %v", t2, a.FirstSeen)
	}
}

// ---------- mergeExtras ----------

func TestMergeExtras_Empty(t *testing.T) {
	var dst map[string]any
	changed := asset.MergeExtras(&dst, nil)
	if changed {
		t.Error("empty src: want false")
	}
}

func TestMergeExtras_NilDst(t *testing.T) {
	var dst map[string]any
	changed := asset.MergeExtras(&dst, map[string]any{"k": "v"})
	if !changed {
		t.Error("expected changed=true")
	}
	if dst["k"] != "v" {
		t.Errorf("dst[k]: want v, got %v", dst["k"])
	}
}

func TestMergeExtras_ScalarKeptExisting(t *testing.T) {
	dst := map[string]any{"k": "old"}
	changed := asset.MergeExtras(&dst, map[string]any{"k": "new"})
	if changed {
		t.Error("scalar existing: expected unchanged")
	}
	if dst["k"] != "old" {
		t.Errorf("dst[k]: want old (unchanged), got %v", dst["k"])
	}
}

func TestMergeExtras_MergeStringSlice(t *testing.T) {
	dst := map[string]any{"k": []string{"a", "b"}}
	changed := asset.MergeExtras(&dst, map[string]any{"k": []string{"b", "c"}})
	if !changed {
		t.Error("expected changed=true")
	}
	got := dst["k"].([]string)
	if len(got) != 3 {
		t.Errorf("len: want 3, got %d (%v)", len(got), got)
	}
}

func TestMergeExtras_SkipNilValue(t *testing.T) {
	var dst map[string]any
	changed := asset.MergeExtras(&dst, map[string]any{"k": nil})
	if changed {
		t.Error("nil value: should not change")
	}
}

func TestMergeExtras_AppendAnySliceToStringSlice(t *testing.T) {
	dst := map[string]any{"k": []any{"a", "b"}}
	changed := asset.MergeExtras(&dst, map[string]any{"k": []string{"c", "d"}})
	if !changed {
		t.Error("expected changed=true")
	}
}

func TestMergeExtras_AppendStringSliceToAnySlice(t *testing.T) {
	dst := map[string]any{"k": []string{"a"}}
	changed := asset.MergeExtras(&dst, map[string]any{"k": []any{"b", "c"}})
	if !changed {
		t.Error("expected changed=true")
	}
}

func TestMergeExtras_AppendAnySliceToAnySlice(t *testing.T) {
	dst := map[string]any{"k": []any{"a"}}
	changed := asset.MergeExtras(&dst, map[string]any{"k": []any{"b", "c"}})
	if !changed {
		t.Error("expected changed=true")
	}
}

func TestMergeExtras_MergeStringSliceNoChange(t *testing.T) {
	dst := map[string]any{"k": []string{"a", "b"}}
	changed := asset.MergeExtras(&dst, map[string]any{"k": []string{"a", "b"}})
	if changed {
		t.Error("identical slices: should be unchanged")
	}
}

// ---------- mergeStrings ----------

func TestMergeStrings_Empty(t *testing.T) {
	out, changed, added := asset.MergeStrings(nil, "a", "b")
	if !changed {
		t.Error("expected changed=true")
	}
	if len(added) != 2 {
		t.Errorf("added len: want 2, got %d", len(added))
	}
	if len(out) != 2 {
		t.Errorf("out len: want 2, got %d", len(out))
	}
}

func TestMergeStrings_DuplicateSkipped(t *testing.T) {
	out, changed, added := asset.MergeStrings([]string{"a", "b"}, "b", "c")
	if !changed {
		t.Error("expected changed=true")
	}
	if len(added) != 1 || added[0] != "c" {
		t.Errorf("added: want [c], got %v", added)
	}
	if len(out) != 3 {
		t.Errorf("out: want 3, got %v", out)
	}
}

func TestMergeStrings_EmptyIncomingSkipped(t *testing.T) {
	out, changed, _ := asset.MergeStrings([]string{"a"}, "", "b")
	if !changed {
		t.Error("expected changed=true")
	}
	if len(out) != 2 {
		t.Errorf("out: want 2, got %v", out)
	}
}

func TestMergeStrings_AllEmpty(t *testing.T) {
	out, changed, _ := asset.MergeStrings([]string{"a"}, "")
	if changed {
		t.Error("all empty: should be unchanged")
	}
	if len(out) != 1 {
		t.Errorf("out: want 1, got %v", out)
	}
}

// ---------- mergeServices ----------

func TestMergeServices_Empty(t *testing.T) {
	out, changed, _ := asset.MergeServices(nil, asset.Service{Protocol: "tcp", Port: 80})
	if !changed {
		t.Error("expected changed=true")
	}
	if len(out) != 1 {
		t.Errorf("out len: want 1, got %d", len(out))
	}
}

func TestMergeServices_DuplicateSkipped(t *testing.T) {
	svc := asset.Service{Protocol: "tcp", Port: 80}
	out, changed, added := asset.MergeServices([]asset.Service{svc}, svc)
	if changed {
		t.Error("duplicate should be skipped")
	}
	if added != nil {
		t.Errorf("added should be empty: %v", added)
	}
	if len(out) != 1 {
		t.Errorf("out: want 1, got %d", len(out))
	}
}

func TestMergeServices_SkipInvalid(t *testing.T) {
	out, changed, _ := asset.MergeServices(nil, asset.Service{Protocol: "", Port: 0})
	if changed {
		t.Error("invalid service should be skipped")
	}
	if out != nil {
		t.Errorf("out should be nil, got %v", out)
	}
}

func TestMergeServices_DifferentPorts(t *testing.T) {
	out, _, _ := asset.MergeServices(
		[]asset.Service{{Protocol: "tcp", Port: 80}},
		asset.Service{Protocol: "tcp", Port: 443},
	)
	if len(out) != 2 {
		t.Errorf("out: want 2, got %d", len(out))
	}
}

func TestMergeServices_ClientVsServer(t *testing.T) {
	out, _, _ := asset.MergeServices(
		[]asset.Service{{Protocol: "tcp", Port: 80}},
		asset.Service{Protocol: "tcp", Port: 80, IsClient: true},
	)
	if len(out) != 2 {
		t.Errorf("client/server should be distinct, got %d", len(out))
	}
}

// ---------- macKey / GenerateAssetID ----------

func TestMacKey_Valid(t *testing.T) {
	id := asset.GenerateAssetID(mustMAC("AA:BB:CC:DD:EE:FF"))
	if string(id) != "mac:aa:bb:cc:dd:ee:ff" {
		t.Errorf("got %q", string(id))
	}
}

func TestMacKey_Empty(t *testing.T) {
	if got := asset.GenerateAssetID(nil); got != "" {
		t.Errorf("nil: want empty, got %q", got)
	}
	if got := asset.GenerateAssetID(net.HardwareAddr{}); got != "" {
		t.Errorf("zero-len: want empty, got %q", got)
	}
}

// ---------- Observation.Valid ----------

func TestObservationValid_Valid(t *testing.T) {
	o := asset.Observation{
		Source:     asset.SourceARP,
		ObservedAt: time.Now(),
		MAC:        mustMAC("aa:bb:cc:dd:ee:ff"),
	}
	if !o.Valid() {
		t.Error("expected valid")
	}
}

func TestObservationValid_MissingSource(t *testing.T) {
	o := asset.Observation{ObservedAt: time.Now(), MAC: mustMAC("aa:bb:cc:dd:ee:ff")}
	if o.Valid() {
		t.Error("missing source: should be invalid")
	}
}

func TestObservationValid_MissingTime(t *testing.T) {
	o := asset.Observation{Source: asset.SourceARP, MAC: mustMAC("aa:bb:cc:dd:ee:ff")}
	if o.Valid() {
		t.Error("missing time: should be invalid")
	}
}

func TestObservationValid_MissingMAC(t *testing.T) {
	o := asset.Observation{Source: asset.SourceARP, ObservedAt: time.Now()}
	if o.Valid() {
		t.Error("missing MAC: should be invalid")
	}
}

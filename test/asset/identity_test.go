package asset_test

import (
	"testing"

	"passivediscovery/internal/asset"
)

// IdentityIndex — covered scenarios:
//   1. Resolve returns bound MAC
//   2. Resolve unbound MAC returns false
//   3. Bind + Resolve round-trip
//   4. Bind same MAC to different ID overwrites
//   5. Unbind removes binding
//   6. Unbind non-existent is no-op

func TestIdentityIndex_BindAndResolve(t *testing.T) {
	t.Parallel()
	idx := asset.NewIdentityIndex()
	mac := mustMAC(t, "aa:bb:cc:dd:ee:01")
	id := asset.GenerateAssetID(mac)

	idx.Bind(id, mac)

	gotID, ok := idx.Resolve(mac)
	if !ok {
		t.Fatal("expected to resolve MAC")
	}
	if gotID != id {
		t.Errorf("expected ID=%q, got %q", id, gotID)
	}
}

func TestIdentityIndex_UnboundMAC(t *testing.T) {
	t.Parallel()
	idx := asset.NewIdentityIndex()
	mac := mustMAC(t, "aa:bb:cc:dd:ee:02")

	_, ok := idx.Resolve(mac)
	if ok {
		t.Error("expected unbound MAC to not resolve")
	}
}

func TestIdentityIndex_BindOverwrite(t *testing.T) {
	t.Parallel()
	idx := asset.NewIdentityIndex()
	mac := mustMAC(t, "aa:bb:cc:dd:ee:03")
	id1 := asset.AssetID("old-id")
	id2 := asset.AssetID("new-id")

	idx.Bind(id1, mac)
	idx.Bind(id2, mac) // overwrite

	gotID, ok := idx.Resolve(mac)
	if !ok {
		t.Fatal("expected to resolve")
	}
	if gotID != id2 {
		t.Errorf("expected overwritten ID=%q, got %q", id2, gotID)
	}
}

func TestIdentityIndex_Unbind(t *testing.T) {
	t.Parallel()
	idx := asset.NewIdentityIndex()
	mac := mustMAC(t, "aa:bb:cc:dd:ee:04")
	id := asset.GenerateAssetID(mac)

	idx.Bind(id, mac)
	idx.Unbind(id)

	_, ok := idx.Resolve(mac)
	if ok {
		t.Error("expected MAC to not resolve after Unbind")
	}
}

func TestIdentityIndex_UnbindNonExistent(t *testing.T) {
	t.Parallel()
	idx := asset.NewIdentityIndex()
	idx.Unbind(asset.AssetID("doesnt-exist"))
	// should not panic
}

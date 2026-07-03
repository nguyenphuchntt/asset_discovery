package asset

// IdentityResolver maps identifiers to AssetIDs. The Manager holds one and is
// the only writer; readers go through Manager.Apply / Manager.Get, not the
// resolver directly.
type IdentityResolver interface {
	// Resolve returns the asset IDs currently bound to any of the supplied
	// identifiers. An empty result means "new asset"; multiple results mean
	// "this observation bridges two previously-separate assets — merge them".
	Resolve(ids []Identifier) []AssetID

	// Bind every identifier in the slice to the given asset. If a key was
	// previously bound to a different asset, that binding is removed (the
	// resolver follows a "steal, not duplicate" rule: each key belongs to
	// exactly one asset).
	Bind(id AssetID, ids []Identifier)

	// Unbind removes every key currently bound to the given asset.
	Unbind(id AssetID)
}

// IdentityIndex is the default in-memory implementation of IdentityResolver.
//
// Two maps are kept in sync: byKey answers "which asset owns this key?",
// byID answers "which keys does this asset own?".
type IdentityIndex struct {
	byKey map[string]AssetID
	byID  map[AssetID][]string
}

func NewIdentityIndex() *IdentityIndex {
	return &IdentityIndex{
		byKey: make(map[string]AssetID),
		byID:  make(map[AssetID][]string),
	}
}

func (x *IdentityIndex) Resolve(ids []Identifier) []AssetID {
	var out []AssetID
	seen := make(map[AssetID]struct{})
	for _, key := range uniqueKeys(ids) {
		id, ok := x.byKey[key]
		if !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func (x *IdentityIndex) Bind(id AssetID, ids []Identifier) {
	for _, key := range uniqueKeys(ids) {
		if prev, ok := x.byKey[key]; ok {
			if prev == id {
				continue
			}
			x.removeKeyFromID(prev, key)
		}
		x.byKey[key] = id
		x.byID[id] = append(x.byID[id], key)
	}
}

func (x *IdentityIndex) Unbind(id AssetID) {
	for _, key := range x.byID[id] {
		if x.byKey[key] == id {
			delete(x.byKey, key)
		}
	}
	delete(x.byID, id)
}

// removeKeyFromID drops a single key from an asset's key list and prunes the
// entry when the list becomes empty.
func (x *IdentityIndex) removeKeyFromID(id AssetID, key string) {
	keys := x.byID[id]
	for i, k := range keys {
		if k == key {
			x.byID[id] = append(keys[:i], keys[i+1:]...)
			break
		}
	}
	if len(x.byID[id]) == 0 {
		delete(x.byID, id)
	}
}
package asset

type IdentityResolver interface {
	// Resolve returns the asset IDs currently bound to any identifier in the
	// subject. An empty result means the subject is belong to a new asset
	Resolve(subject IdentitySet) []AssetID

	// Bind every identifier in the subject to the given asset ID.
	Bind(id AssetID, subject IdentitySet)


	Unbind(id AssetID)
}

type IdentityIndex struct {
	byKey map[string]AssetID   // (identifier:assetID)
	byID  map[AssetID][]string // (assetID:[identifier])
}

func NewIdentityIndex() *IdentityIndex {
	return &IdentityIndex{
		byKey: make(map[string]AssetID),
		byID:  make(map[AssetID][]string),
	}
}

// return asset hold the IdentitySet, empty means new asset
func (x *IdentityIndex) Resolve(subject IdentitySet) []AssetID {
	var ids []AssetID
	seen := make(map[AssetID]struct{})
	for _, key := range subject.Keys() { // all identity keys
		id, ok := x.byKey[key]
		if !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// Bind every identifier in the subject to AssetId.
func (x *IdentityIndex) Bind(id AssetID, subject IdentitySet) {
	for _, key := range subject.Keys() {
		if prev, ok := x.byKey[key]; ok {
			if prev == id { // prev asset == new asset
				continue
			}
			x.removeKeyFromID(prev, key) // else: rm key from prev asset
		}
		x.byKey[key] = id
		x.byID[id] = append(x.byID[id], key)
	}
}

// Removes bindings between assetID and its keys
func (x *IdentityIndex) Unbind(id AssetID) {
	for _, key := range x.byID[id] {
		if x.byKey[key] == id {
			delete(x.byKey, key)
		}
	}
	delete(x.byID, id)
}

// remove a key from byID map
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

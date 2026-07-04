package asset

import "net"

type IdentityResolver interface {
	Resolve(mac net.HardwareAddr) (AssetID, bool)
	Bind(id AssetID, mac net.HardwareAddr)
	Unbind(id AssetID)
}

type IdentityIndex struct {
	byKey map[string]AssetID
	byID  map[AssetID]string
}

func NewIdentityIndex() *IdentityIndex {
	return &IdentityIndex{
		byKey: make(map[string]AssetID),
		byID:  make(map[AssetID]string),
	}
}

func (x *IdentityIndex) Resolve(mac net.HardwareAddr) (AssetID, bool) {
	id, ok := x.byKey[macKey(mac)]
	return id, ok
}

func (x *IdentityIndex) Bind(id AssetID, mac net.HardwareAddr) {
	if len(mac) == 0 {
		return
	}
	k := macKey(mac)
	x.byKey[k] = id
	x.byID[id] = k
}

func (x *IdentityIndex) Unbind(id AssetID) {
	if k, ok := x.byID[id]; ok {
		if x.byKey[k] == id {
			delete(x.byKey, k)
		}
		delete(x.byID, id)
	}
}
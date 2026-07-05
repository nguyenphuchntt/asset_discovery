package asset

import (
	"fmt"
	"slices"
	"sync"
	"time"

	internalConfig "passivediscovery/internal/config"
)

type VendorResolver interface {
	VendorForMAC(mac string) (string, bool)
}

type AssetManager interface {
	Apply(obs Observation) (ApplyResult, error)
	Get(id AssetID) (AssetSnapshot, bool)
	Snapshot() []AssetSnapshot
	Sweep(now time.Time, offlineAfter time.Duration) []Event
	DrainDirty() []AssetSnapshot
	DrainEvents() []Event
}

type ApplyAction string

const (
	ActionCreated ApplyAction = "created"
	ActionUpdated ApplyAction = "updated"
	ActionMerged  ApplyAction = "merged"
)

type ApplyResult struct {
	AssetID AssetID
	Action  ApplyAction
}

type Manager struct {
	mu       sync.RWMutex // Sweep, Apply
	assets   map[AssetID]*Asset
	resolver IdentityResolver
	events   []Event
	dirty    map[AssetID]struct{}

	vendor VendorResolver
}

func WithVendorResolver(v VendorResolver) ManagerOption {
	return func(m *Manager) { m.vendor = v }
}

var _ AssetManager = (*Manager)(nil)

type ManagerOption func(*Manager)

func NewManager(resolver IdentityResolver, opts ...ManagerOption) *Manager {
	if resolver == nil {
		resolver = NewIdentityIndex()
	}
	m := &Manager{
		assets:   make(map[AssetID]*Asset),
		resolver: resolver,
		dirty:    make(map[AssetID]struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Manager) mergeInto(a *Asset, obs Observation) MergeResult {
	mr := mergeObservation(a, obs)

	if m.vendor == nil || a.MACVendor != "" || len(a.MAC) == 0 {
		return mr
	}
	name, ok := m.vendor.VendorForMAC(a.MAC.String())
	if !ok || name == "" {
		return mr
	}
	a.MACVendor = name
	mr.Changed = true
	return mr
}

func (m *Manager) Apply(obs Observation) (ApplyResult, error) {
	if !obs.Valid() {
		return ApplyResult{}, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var res ApplyResult
	emit := func(t EventType, id AssetID, detail string) {
		m.events = append(m.events, newEvent(t, id, obs.ObservedAt, obs.Source, ""))
	}

	if existingID, ok := m.resolver.Resolve(obs.MAC); ok {
		a := m.assets[existingID]
		mr := m.mergeInto(a, obs)
		m.resolver.Bind(a.ID, obs.MAC)
		if a.Status == StatusOffline {
			a.Status = StatusOnline
			mr.Changed = true
			emit(EventStatusOnline, a.ID, "")
		}
		m.emitFirstSeen(a.ID, mr, emit)
		if mr.Changed {
			m.markDirty(a.ID)
		}
		res.AssetID = a.ID
		res.Action = ActionUpdated
	} else {
		id := GenerateAssetID(obs.MAC)
		if id == "" {
			return ApplyResult{}, nil
		}
		a := &Asset{
			ID:     id,
			MAC:    CloneMAC(obs.MAC),
			Status: StatusOnline,
		}
		mr := m.mergeInto(a, obs)
		m.assets[id] = a
		m.resolver.Bind(id, obs.MAC)
		m.markDirty(id)
		m.emitFirstSeen(id, mr, emit)
		res.AssetID = id
		res.Action = ActionCreated
		emit(EventAssetCreated, id, "")
	}

	return res, nil
}

// get a Asset snapshot via its Id 
func (m *Manager) Get(id AssetID) (AssetSnapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.assets[id]
	if !ok {
		return AssetSnapshot{}, false
	}
	return a.Snapshot(), true
}

// return all assets as snapshot 
func (m *Manager) Snapshot() []AssetSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]AssetSnapshot, 0, len(m.assets))
	for _, a := range m.assets {
		out = append(out, a.Snapshot())
	}
	return out
}


func (m *Manager) Sweep(now time.Time, offlineAfter time.Duration) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	var events []Event
	for _, a := range m.assets {
		changed := sweepIPMap(&a.IPv4s, now)
		changed = sweepIPMap(&a.IPv6s, now) || changed
		if a.Status == StatusOnline && now.Sub(a.LastSeen) > offlineAfter {
			a.Status = StatusOffline
			changed = true
			e := newEvent(EventStatusOffline, a.ID, now, "", "asset went offline")
			m.events = append(m.events, e)
			events = append(events, e)
		}
		if changed {
			m.markDirty(a.ID)
		}
	}
	return events
}

// track IP active
func sweepIPMap(m *map[string]IPEntry, now time.Time) bool {
	changed := false
	for ip, e := range *m {
		if e.Lease == 0 || e.Lease <= 0 {
			continue
		}
		if now.Sub(e.LastSeen) > e.Lease+internalConfig.IpGrace && e.IsActive {
			e.IsActive = false
			(*m)[ip] = e
			changed = true
		}
	}
	return changed
}

func (m *Manager) DrainDirty() []AssetSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]AssetSnapshot, 0, len(m.dirty))
	for id := range m.dirty {
		if a, ok := m.assets[id]; ok {
			out = append(out, a.Snapshot())
		}
	}
	clear(m.dirty)
	return out
}

func (m *Manager) DrainEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.events
	m.events = nil
	return out
}

func (m *Manager) LoadSnapshots(snapshots []AssetSnapshot) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	loaded := 0
	for _, s := range snapshots {
		if s.ID == "" || len(s.MAC) == 0 {
			continue
		}
		a := assetFromSnapshot(s)
		existing, ok := m.assets[a.ID]
		if ok && !a.LastSeen.After(existing.LastSeen) {
			continue
		}
		m.assets[a.ID] = a
		m.resolver.Bind(a.ID, a.MAC)
		loaded++
	}
	return loaded
}

func (m *Manager) markDirty(id AssetID) {
	if id == "" {
		return
	}
	m.dirty[id] = struct{}{}
}

func (m *Manager) emitFirstSeen(id AssetID, mr MergeResult, emit func(EventType, AssetID, string)) {
	for _, ip := range mr.NewIPv4s {
		emit(EventIPFirstSeen, id, "IPv4 first seen: "+ip)
	}
	for _, ip := range mr.NewIPv6s {
		emit(EventIPFirstSeen, id, "IPv6 first seen: "+ip)
	}
	for _, h := range mr.NewHostnames {
		emit(EventHostnameFirstSeen, id, "hostname first seen: "+h)
	}
	for _, s := range mr.NewServices {
		emit(EventServiceFirstSeen, id, "service first seen: "+s.Protocol+" "+fmt.Sprintf("%d", s.Port))
	}
}

func assetFromSnapshot(s AssetSnapshot) *Asset {
	return &Asset{
		ID:         s.ID,
		MAC:        CloneMAC(s.MAC),
		IPv4s:      cloneIPMap(s.IPv4s),
		IPv6s:      cloneIPMap(s.IPv6s),
		Hostnames:  slices.Clone(s.Hostnames),
		Services:   slices.Clone(s.Services),
		MACVendor:  s.MACVendor,
		DeviceType: s.DeviceType,
		Model:      s.Model,
		OS:         s.OS,
		Extra:      cloneExtras(s.Extra),
		FirstSeen:  s.FirstSeen,
		LastSeen:   s.LastSeen,
		SeenCount:  s.SeenCount,
		Status:     s.Status,
	}
}

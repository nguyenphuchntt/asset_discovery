package asset

import (
	"sync"
	"time"
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

	vendor VendorResolver
}

var _ AssetManager = (*Manager)(nil)

type ManagerOption func(*Manager)

func WithVendorResolver(v VendorResolver) ManagerOption {
	return func(m *Manager) { m.vendor = v }
}

func NewManager(resolver IdentityResolver, opts ...ManagerOption) *Manager {
	if resolver == nil {
		resolver = NewIdentityIndex()
	}
	m := &Manager{
		assets:   make(map[AssetID]*Asset),
		resolver: resolver,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Manager) Apply(obs Observation) (ApplyResult, error) {
	if !obs.Valid() {
		return ApplyResult{}, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var res ApplyResult
	emit := func(t EventType, id AssetID, detail string) {
		m.events = append(m.events, newEvent(t, id, obs.ObservedAt, obs.Source, detail))
	}

	if existingID, ok := m.resolver.Resolve(obs.MAC); ok {
		a := m.assets[existingID]
		m.mergeInto(a, obs)
		m.resolver.Bind(a.ID, obs.MAC)
		if a.Status == StatusOffline {
			a.Status = StatusOnline
			emit(EventStatusOnline, a.ID, "asset back online")
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
		m.mergeInto(a, obs)
		m.assets[id] = a
		m.resolver.Bind(id, obs.MAC)
		res.AssetID = id
		res.Action = ActionCreated
		emit(EventAssetCreated, id, "asset created")
	}

	return res, nil
}

func (m *Manager) Get(id AssetID) (AssetSnapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.assets[id]
	if !ok {
		return AssetSnapshot{}, false
	}
	return a.Snapshot(), true
}

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
		sweepIPMap(&a.IPv4s, now)
		sweepIPMap(&a.IPv6s, now)
		if a.Status == StatusOnline && now.Sub(a.LastSeen) > offlineAfter {
			a.Status = StatusOffline
			e := newEvent(EventStatusOffline, a.ID, now, "", "asset went offline")
			m.events = append(m.events, e)
			events = append(events, e)
		}
	}
	return events
}

const ipGrace = 5 * time.Minute
func sweepIPMap(m *map[string]IPEntry, now time.Time) {
	for ip, e := range *m {
		if e.Lease == 0 || e.Lease <= 0 {
			continue
		}
		if now.Sub(e.LastSeen) > e.Lease+ipGrace && e.IsActive {
			e.IsActive = false
			(*m)[ip] = e
		}
	}
}

func (m *Manager) DrainDirty() []AssetSnapshot {
	panic("TODO: implement (Phase 2 — persist)")
}

func (m *Manager) DrainEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.events
	m.events = nil
	return out
}

func (m *Manager) mergeInto(a *Asset, obs Observation) {
	mergeObservation(a, obs)

	if m.vendor == nil || a.MACVendor != "" || len(a.MAC) == 0 {
		return
	}
	name, ok := m.vendor.VendorForMAC(a.MAC.String())
	if !ok || name == "" {
		return
	}
	a.MACVendor = name
}
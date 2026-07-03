package asset

import (
	"sync"
	"time"
)

// VendorResolver looks up the canonical vendor name for a MAC address
// (typically backed by an IEEE OUI database). The result string is stored on
// Asset.MACVendor. Returning ok=false (or an empty string) means "no vendor
// known" and the asset is left without a vendor label.
type VendorResolver interface {
	VendorForMAC(mac string) (string, bool)
}

// AssetManager is the in-memory domain facade. The pipeline calls Apply for
// every observation; lifecycle calls Sweep on a timer; persist calls Drain*
// to flush changes out.
type AssetManager interface {
	Apply(obs Observation) (ApplyResult, error)
	Get(id AssetID) (AssetSnapshot, bool)
	Snapshot() []AssetSnapshot
	Sweep(now time.Time, offlineAfter time.Duration) []Event
	DrainDirty() []AssetSnapshot
	DrainEvents() []Event
}

// ApplyAction is a single-step summary of what Apply did with one observation.
// Callers use this to decide what to log/alert without having to inspect the
// pre/post state of the manager.
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

// Manager is the default in-memory AssetManager. All exported methods are
// safe for concurrent use: mutators (Apply, Sweep, Drain*) take m.mu.Lock();
// readers (Get, Snapshot) take m.mu.RLock().
type Manager struct {
	mu       sync.RWMutex
	assets   map[AssetID]*Asset
	resolver IdentityResolver
	events   []Event

	vendor VendorResolver
}

var _ AssetManager = (*Manager)(nil)

// ManagerOption customises a Manager at construction time. New options
// should be added sparingly — the Manager is meant to be small.
type ManagerOption func(*Manager)

// WithVendorResolver enables MAC-to-vendor enrichment: when an asset's
// MACVendor is empty, the manager will look up the first known MAC against
// the resolver and store the result.
func WithVendorResolver(v VendorResolver) ManagerOption {
	return func(m *Manager) { m.vendor = v }
}

// NewManager builds a Manager backed by the given resolver. A nil resolver
// falls back to a fresh in-memory IdentityIndex.
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

// Apply resolves an observation to an asset and folds it in. Depending on
// how many assets the subject already touches it creates a new asset (0),
// updates one (1), or merges several into one (>1).
//
// Invalid observations are silently dropped (returning a zero ApplyResult and
// nil error): junk packets are normal traffic, not a system error.
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

	ids := m.resolver.Resolve(obs.Identifiers)

	switch len(ids) {
	case 0:
		id := GenerateAssetID(obs.Identifiers)
		if id == "" {
			return ApplyResult{}, nil
		}
		a := &Asset{ID: id, Status: StatusOnline}
		m.mergeInto(a, obs)
		m.assets[id] = a
		m.resolver.Bind(id, obs.Identifiers)
		res.AssetID = id
		res.Action = ActionCreated
		emit(EventAssetCreated, id, "asset created")

	case 1:
		a := m.assets[ids[0]]
		m.mergeInto(a, obs)
		m.resolver.Bind(a.ID, obs.Identifiers)
		if a.Status == StatusOffline {
			a.Status = StatusOnline
			emit(EventStatusOnline, a.ID, "asset back online")
		}
		res.AssetID = a.ID
		res.Action = ActionUpdated

	default:
		primary := m.assets[ids[0]]
		for _, other := range ids[1:] {
			if other == primary.ID {
				continue
			}
			if sec, ok := m.assets[other]; ok {
				mergeAssets(primary, sec)
				m.resolver.Bind(primary.ID, identifiersOf(sec))
				delete(m.assets, other)
			}
			m.resolver.Unbind(other)
		}
		m.mergeInto(primary, obs)
		m.resolver.Bind(primary.ID, obs.Identifiers)
		primary.Status = StatusOnline
		res.AssetID = primary.ID
		res.Action = ActionMerged
		emit(EventIdentityMerged, primary.ID, "identity merged")
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

// Sweep marks online assets whose LastSeen is older than offlineAfter as
// offline. This is the only online→offline transition; offline→online happens
// in Apply when fresh evidence arrives.
func (m *Manager) Sweep(now time.Time, offlineAfter time.Duration) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	var events []Event
	for _, a := range m.assets {
		if a.Status == StatusOnline && now.Sub(a.LastSeen) > offlineAfter {
			a.Status = StatusOffline
			e := newEvent(EventStatusOffline, a.ID, now, "", "asset went offline")
			m.events = append(m.events, e)
			events = append(events, e)
		}
	}
	return events
}

// DrainDirty returns snapshots of assets changed since the last drain and
// clears the dirty set. Phase 2 (persist) work — currently unimplemented.
func (m *Manager) DrainDirty() []AssetSnapshot {
	panic("TODO: implement (Phase 2 — persist)")
}

// DrainEvents returns and clears buffered lifecycle/audit events.
func (m *Manager) DrainEvents() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.events
	m.events = nil
	return out
}

// mergeInto folds an observation into an asset and applies optional vendor
// enrichment. Callers must hold m.mu.
func (m *Manager) mergeInto(a *Asset, obs Observation) {
	mergeObservation(a, obs)

	if m.vendor == nil || a.MACVendor != "" {
		return
	}
	for _, mac := range a.MACs {
		name, ok := m.vendor.VendorForMAC(mac.String())
		if !ok || name == "" {
			continue
		}
		a.MACVendor = name
		return
	}
}

// identifiersOf reconstructs an identifier list from an asset's indexable
// fields. Used when merging two assets: secondary's identifiers need to be
// re-bound to the primary before the secondary is dropped.
func identifiersOf(a *Asset) []Identifier {
	out := make([]Identifier, 0, len(a.MACs)+len(a.IPv4s)+len(a.IPv6s)+len(a.Hostnames))
	add := func(t IdentifierType, value string) {
		if value != "" {
			out = append(out, Identifier{Type: t, Value: value})
		}
	}
	for _, mac := range a.MACs {
		add(IdentifierMAC, mac.String())
	}
	for _, ip := range a.IPv4s {
		add(IdentifierIPv4, ip.String())
	}
	for _, ip := range a.IPv6s {
		if ip.To4() != nil {
			continue
		}
		add(IdentifierIPv6, ip.String())
	}
	for _, h := range a.Hostnames {
		add(IdentifierHostname, h)
	}
	return out
}
package asset

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	internalConfig "passivediscovery/internal/config"
	"passivediscovery/internal/stats"
)

type VendorResolver interface {
	VendorForMAC(mac string) (string, bool)
}

type Hydrator interface {
	LoadAssetByMAC(ctx context.Context, mac string) (*AssetSnapshot, error)
}

type AssetManager interface {
	Apply(ctx context.Context, obs Observation) (ApplyResult, error)
	Get(id AssetID) (AssetSnapshot, bool)
	Snapshot() []AssetSnapshot
	Sweep(now time.Time, offlineAfter time.Duration) int
	EvictStale(now time.Time, evictAfter time.Duration) int
	DrainDirty() []AssetSnapshot
	RecordPacket()
	PacketsReceived() uint64
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

const ShardCount = 16

type shard struct {
	mu     sync.RWMutex
	assets map[AssetID]*Asset
	dirty  map[AssetID]struct{}
}

type Manager struct {
	shards      [ShardCount]*shard
	resolver    *ShardedResolver
	vendor      VendorResolver
	hydrator    Hydrator
	packetsRecv atomic.Uint64
	packetRate  *stats.PacketRate
}

type ShardedResolver struct {
	shards [ShardCount]struct {
		sync.RWMutex
		byKey map[string]AssetID
		byID  map[AssetID]string
	}
}

func NewShardedResolver() *ShardedResolver {
	r := &ShardedResolver{}
	for i := range r.shards {
		r.shards[i].byKey = make(map[string]AssetID)
		r.shards[i].byID = make(map[AssetID]string)
	}
	return r
}

func shardIndex(mac net.HardwareAddr) int {
	if len(mac) == 0 {
		return 0
	}
	var sum int
	for _, b := range mac {
		sum += int(b)
	}
	return sum % ShardCount
}

func (r *ShardedResolver) Resolve(mac net.HardwareAddr) (AssetID, int, bool) {
	idx := shardIndex(mac)
	r.shards[idx].RLock()
	defer r.shards[idx].RUnlock()
	id, ok := r.shards[idx].byKey[macKey(mac)]
	return id, idx, ok
}

func (r *ShardedResolver) Bind(id AssetID, mac net.HardwareAddr, idx int) {
	if len(mac) == 0 {
		return
	}
	if idx < 0 || idx >= ShardCount {
		idx = shardIndex(mac)
	}
	r.shards[idx].Lock()
	defer r.shards[idx].Unlock()
	k := macKey(mac)
	r.shards[idx].byKey[k] = id
	r.shards[idx].byID[id] = k
}

// Unbind removes the MAC↔ID binding. Used during eviction.
func (r *ShardedResolver) Unbind(id AssetID, idx int) {
	if idx < 0 || idx >= ShardCount {
		return
	}
	r.shards[idx].Lock()
	defer r.shards[idx].Unlock()
	if k, ok := r.shards[idx].byID[id]; ok {
		if r.shards[idx].byKey[k] == id {
			delete(r.shards[idx].byKey, k)
		}
		delete(r.shards[idx].byID, id)
	}
}

var _ AssetManager = (*Manager)(nil)

type ManagerOption func(*Manager)

func WithVendorResolver(v VendorResolver) ManagerOption {
	return func(m *Manager) { m.vendor = v }
}

func NewManager(_ IdentityResolver, opts ...ManagerOption) *Manager {
	m := &Manager{
		resolver:  NewShardedResolver(),
		packetRate: stats.NewPacketRate(time.Second, 60),
	}
	for i := range m.shards {
		m.shards[i] = &shard{
			assets: make(map[AssetID]*Asset),
			dirty:  make(map[AssetID]struct{}),
		}
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Manager) SetHydrator(h Hydrator) { m.hydrator = h }

func (m *Manager) RecordPacket()          { m.packetsRecv.Add(1); m.packetRate.Inc() }
func (m *Manager) PacketsReceived() uint64  { return m.packetsRecv.Load() }
func (m *Manager) PacketsPerSec() float64   { return m.packetRate.Rate() }
func (m *Manager) PacketRate() *stats.PacketRate { return m.packetRate }
func (m *Manager) SetInitialCounters(packets uint64) { m.packetsRecv.Store(packets) }
func (m *Manager) AssetsCount() uint64 {
	var total uint64
	for _, s := range m.shards {
		s.mu.RLock()
		total += uint64(len(s.assets))
		s.mu.RUnlock()
	}
	return total
}

func (m *Manager) shardForIdx(idx int) *shard { return m.shards[idx] }

func (m *Manager) mergeInto(a *Asset, obs Observation) MergeResult {
	mr := mergeObservation(a, obs)

	// OUI vendor lookup only when missing
	if m.vendor != nil && a.MACVendor == "" && len(a.MAC) > 0 {
		if name, ok := m.vendor.VendorForMAC(a.MAC.String()); ok && name != "" {
			a.MACVendor = name
			mr.Changed = true
		}
	}

	// Fallback: infer DeviceType/OS from vendor + hostname when still empty
	if a.DeviceType == "" || a.OS == "" {
		dt, osName := inferFromVendorHostname(a.MACVendor, a.Hostnames)
		if a.DeviceType == "" && dt != "" {
			a.DeviceType = dt
			mr.Changed = true
		}
		if a.OS == "" && osName != "" {
			a.OS = osName
			mr.Changed = true
		}
	}

	return mr
}

// inferFromVendorHostname tries to guess DeviceType and OS from the MAC
// vendor name and hostnames when no explicit clue (SSDP/DHCP/mDNS) was
// provided.  Returns empty strings when nothing can be inferred.
func inferFromVendorHostname(vendor string, hostnames []string) (deviceType, os string) {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "apple"):
		return "", "ios"
	case strings.Contains(v, "samsung"), strings.Contains(v, "huawei"),
		strings.Contains(v, "Anthropic"), strings.Contains(v, "google"):
		return "mobile", "android"
	case strings.Contains(v, "microsoft"):
		return "computer", "windows"
	case strings.Contains(v, "tp-link"), strings.Contains(v, "ubiquiti"),
		strings.Contains(v, "netgear"):
		return "router", "linux"
	}
	for _, h := range hostnames {
		h = strings.ToLower(h)
		if strings.HasPrefix(h, "android-") || strings.Contains(h, ".android") {
			return "mobile", "android"
		}
		if strings.HasPrefix(h, "iphone") || strings.HasPrefix(h, "ipad") {
			return "mobile", "ios"
		}
	}
	return "", ""
}

func (m *Manager) Apply(ctx context.Context, obs Observation) (ApplyResult, error) {
	if !obs.Valid() {
		return ApplyResult{}, nil
	}
	// Resolve identity — lock-free read to find the shard.
	existingID, idx, exists := m.resolver.Resolve(obs.MAC)

	// Lock shard.
	sh := m.shardForIdx(idx)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	// On-demand hydrate: MAC exists in DB but not in memory (evicted or cold).
	if !exists && m.hydrator != nil {
		if snap, _ := m.hydrator.LoadAssetByMAC(ctx, obs.MAC.String()); snap != nil {
			a := assetFromSnapshot(*snap)
			sh.assets[a.ID] = a
			m.resolver.Bind(a.ID, a.MAC, idx)
			existingID = a.ID
			exists = true
		}
	}

	var res ApplyResult
	switch {
	case exists:
		a := sh.assets[existingID]
		mr := m.mergeInto(a, obs)
		m.resolver.Bind(a.ID, obs.MAC, idx)
		if a.Status == StatusOffline {
			a.Status = StatusOnline
			mr.Changed = true
		}
		if mr.Changed {
			m.markDirty(sh, a.ID)
		}
		res.AssetID = a.ID
		res.Action = ActionUpdated
	default:
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
		sh.assets[id] = a
		m.resolver.Bind(id, obs.MAC, idx)
		m.markDirty(sh, id)
		res.AssetID = id
		res.Action = ActionCreated
	}

	return res, nil
}

func (m *Manager) Get(id AssetID) (AssetSnapshot, bool) {
	for _, sh := range m.shards {
		sh.mu.RLock()
		if a, ok := sh.assets[id]; ok {
			snap := a.Snapshot()
			sh.mu.RUnlock()
			return snap, true
		}
		sh.mu.RUnlock()
	}
	return AssetSnapshot{}, false
}

func (m *Manager) Snapshot() []AssetSnapshot {
	var out []AssetSnapshot
	for _, sh := range m.shards {
		sh.mu.RLock()
		for _, a := range sh.assets {
			out = append(out, a.Snapshot())
		}
		sh.mu.RUnlock()
	}
	return out
}

func (m *Manager) Sweep(now time.Time, offlineAfter time.Duration) int {
	transitions := 0
	for _, sh := range m.shards {
		sh.mu.Lock()
		for _, a := range sh.assets {
			changed := sweepIPMap(&a.IPv4s, now)
			changed = sweepIPMap(&a.IPv6s, now) || changed
			if a.Status == StatusOnline && now.Sub(a.LastSeen) > offlineAfter {
				a.Status = StatusOffline
				changed = true
				transitions++
			}
			if changed {
				m.markDirty(sh, a.ID)
			}
		}
		sh.mu.Unlock()
	}
	return transitions
}

// sweepIPMap giữ nguyên — chỉ thao tác trên 1 asset, không cần external lock.
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

// EvictStale removes assets that are offline and have not been seen for longer
// than evictAfter. Only the in-memory state is cleared; the DB record persists.
func (m *Manager) EvictStale(now time.Time, evictAfter time.Duration) int {
	evicted := 0
	for idx := range m.shards {
		sh := m.shards[idx]
		sh.mu.Lock()
		for id, a := range sh.assets {
			if a.Status == StatusOffline && now.Sub(a.LastSeen) > evictAfter {
				delete(sh.assets, id)
				m.resolver.Unbind(a.ID, idx)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	return evicted
}

func (m *Manager) DrainDirty() []AssetSnapshot {
	var out []AssetSnapshot
	for _, sh := range m.shards {
		sh.mu.Lock()
		for id := range sh.dirty {
			if a, ok := sh.assets[id]; ok {
				out = append(out, a.Snapshot())
			}
		}
		clear(sh.dirty)
		sh.mu.Unlock()
	}
	return out
}

func (m *Manager) LoadSnapshots(snapshots []AssetSnapshot) int {
	byShard := make(map[int][]AssetSnapshot, ShardCount)
	for _, s := range snapshots {
		if s.ID == "" || len(s.MAC) == 0 {
			continue
		}
		idx := shardIndex(s.MAC)
		byShard[idx] = append(byShard[idx], s)
	}

	loaded := 0
	for idx, snaps := range byShard {
		sh := m.shards[idx]
		sh.mu.Lock()
		for _, s := range snaps {
			a := assetFromSnapshot(s)
			existing, ok := sh.assets[a.ID]
			if ok && !a.LastSeen.After(existing.LastSeen) {
				continue
			}
			sh.assets[a.ID] = a
			m.resolver.Bind(a.ID, a.MAC, idx)
			loaded++
		}
		sh.mu.Unlock()
	}
	return loaded
}

func (m *Manager) markDirty(sh *shard, id AssetID) {
	if id == "" {
		return
	}
	sh.dirty[id] = struct{}{}
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

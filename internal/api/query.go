package api

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"passivediscovery/internal/asset"
)

// QueryRepository defines the read-only query surface for the dashboard API.
type QueryRepository interface {
	Ready(ctx context.Context) bool
	ListAssets(ctx context.Context, filter AssetFilter) (*AssetListResponse, error)
	GetAssetDetail(ctx context.Context, id asset.AssetID) (*AssetDetailResponse, error)
	ListEvents(ctx context.Context, filter EventFilter) (*EventListResponse, error)
	ListVendors(ctx context.Context) ([]string, error)
}

type AssetFilter struct {
	Q          string
	Status     string
	Vendor     string
	Source     string
	IP         string
	MAC        string
	Hostname   string
	SeenAfter  time.Time
	SeenBefore time.Time
	Sort       string
	Limit      int
}

type EventFilter struct {
	AssetID string
	Type    string
	After   time.Time
	Before  time.Time
	Limit   int
}

// DBQueryRepo implements QueryRepository against SQLite.
type DBQueryRepo struct {
	db *sql.DB
}

func NewDBQueryRepo(db *sql.DB) *DBQueryRepo {
	return &DBQueryRepo{db: db}
}

func (q *DBQueryRepo) Ready(ctx context.Context) bool {
	return q.db != nil && q.db.PingContext(ctx) == nil
}

// --- ListAssets ---

func (q *DBQueryRepo) ListAssets(ctx context.Context, f AssetFilter) (*AssetListResponse, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var conditions []string
	var args []any

	if f.Q != "" {
		like := "%" + f.Q + "%"
		conditions = append(conditions,
			"(a.mac LIKE ? OR a.mac_vendor LIKE ? OR a.os LIKE ? OR a.device_type LIKE ? OR a.id LIKE ?)")
		args = append(args, like, like, like, like, like)
	}
	if f.Status != "" {
		conditions = append(conditions, "a.status = ?")
		args = append(args, f.Status)
	}
	if f.Vendor != "" {
		conditions = append(conditions, "a.mac_vendor = ?")
		args = append(args, f.Vendor)
	}
	if f.IP != "" {
		conditions = append(conditions, "a.id IN (SELECT asset_id FROM asset_ips WHERE ip = ?)")
		args = append(args, f.IP)
	}
	if f.MAC != "" {
		conditions = append(conditions, "a.mac = ?")
		args = append(args, f.MAC)
	}
	if f.Hostname != "" {
		conditions = append(conditions, "a.id IN (SELECT asset_id FROM asset_hostnames WHERE hostname = ?)")
		args = append(args, f.Hostname)
	}
	if !f.SeenAfter.IsZero() {
		conditions = append(conditions, "a.last_seen >= ?")
		args = append(args, f.SeenAfter.UTC().Format(time.RFC3339Nano))
	}
	if !f.SeenBefore.IsZero() {
		conditions = append(conditions, "a.last_seen <= ?")
		args = append(args, f.SeenBefore.UTC().Format(time.RFC3339Nano))
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	orderBy := "ORDER BY a.last_seen DESC"
	switch f.Sort {
	case "first_seen_asc":
		orderBy = "ORDER BY a.first_seen ASC"
	case "first_seen_desc":
		orderBy = "ORDER BY a.first_seen DESC"
	case "last_seen_asc":
		orderBy = "ORDER BY a.last_seen ASC"
	case "last_seen_desc", "":
		orderBy = "ORDER BY a.last_seen DESC"
	}

	// Fetch one extra row to determine if a next page exists.
	query := fmt.Sprintf(
		`SELECT a.id, a.status, a.mac, a.mac_vendor, a.device_type, a.model, a.os,
		        a.first_seen, a.last_seen, a.seen_count
		 FROM assets a %s %s LIMIT ?`,
		where, orderBy,
	)
	args = append(args, limit+1)

	rows, err := q.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query assets: %w", err)
	}
	defer rows.Close()

	var items []AssetListItem
	var lastSeen string
	for rows.Next() {
		var (
			item      AssetListItem
			macStr    sql.NullString
			seenCount uint64
		)
		if err := rows.Scan(
			&item.ID, &item.Status, &macStr, &item.Vendor, &item.DeviceType,
			&item.Model, &item.OS, &item.FirstSeen, &item.LastSeen, &seenCount,
		); err != nil {
			return nil, fmt.Errorf("scan asset: %w", err)
		}
		item.SeenCount = seenCount
		if macStr.Valid {
			item.MAC = macStr.String
		}
		lastSeen = item.LastSeen

		if len(items) < limit {
			items = append(items, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load child rows for displayed assets.
	for i := range items {
		items[i].CurrentIPs, _ = q.loadActiveIPs(ctx, items[i].ID)
		items[i].Hostnames, _ = q.loadHostnames(ctx, items[i].ID)
	}

	nextCursor := ""
	if len(items) == limit && lastSeen != "" {
		nextCursor = lastSeen
	}
	return &AssetListResponse{
		Items: emptyAssetSlice(items),
		Page:  PageInfo{Limit: limit, NextCursor: nextCursor},
	}, nil
}

func (q *DBQueryRepo) loadActiveIPs(ctx context.Context, assetID string) ([]string, error) {
	rows, err := q.db.QueryContext(ctx,
		`SELECT ip FROM asset_ips WHERE asset_id = ? AND is_active = 1`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (q *DBQueryRepo) loadHostnames(ctx context.Context, assetID string) ([]string, error) {
	rows, err := q.db.QueryContext(ctx,
		`SELECT hostname FROM asset_hostnames WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		names = append(names, h)
	}
	return names, rows.Err()
}

// --- GetAssetDetail ---

func (q *DBQueryRepo) GetAssetDetail(ctx context.Context, id asset.AssetID) (*AssetDetailResponse, error) {
	const assetQ = `SELECT id, status, mac, mac_vendor, device_type, model, os, first_seen, last_seen
		FROM assets WHERE id = ?`

	var (
		resp   AssetDetailResponse
		macStr sql.NullString
	)
	resp.Asset = AssetIdentity{}
	err := q.db.QueryRowContext(ctx, assetQ, string(id)).Scan(
		&resp.Asset.ID, &resp.Asset.Status, &macStr, &resp.Asset.Vendor,
		&resp.Asset.DeviceType, &resp.Asset.Model, &resp.Asset.OS,
		&resp.Asset.FirstSeen, &resp.Asset.LastSeen,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query asset detail: %w", err)
	}
	if macStr.Valid {
		resp.Asset.MAC = macStr.String
	}

	resp.IPv4History, _ = q.loadIPHistory(ctx, string(id), 4)
	resp.IPv6History, _ = q.loadIPHistory(ctx, string(id), 6)
	resp.Hostnames, _ = q.loadHostnames(ctx, string(id))

	// Services
	svcRows, err := q.db.QueryContext(ctx,
		`SELECT protocol, port, name, version, product, vendor, banner, is_active, last_seen
		 FROM asset_services WHERE asset_id = ? ORDER BY port`, string(id))
	if err == nil {
		defer svcRows.Close()
		for svcRows.Next() {
			var svc ServiceEntry
			var isActive int
			if err := svcRows.Scan(&svc.Protocol, &svc.Port, &svc.Name, &svc.Version,
				&svc.Product, &svc.Vendor, &svc.Banner, &isActive, &svc.LastSeen); err != nil {
				continue
			}
			svc.IsActive = isActive != 0
			resp.Services = append(resp.Services, svc)
		}
		svcRows.Err()
	}

	// Recent events (latest 50)
	evtRows, err := q.db.QueryContext(ctx,
		`SELECT e.id, e.asset_id, e.type, e.at, e.source, e.detail
		 FROM asset_events e WHERE e.asset_id = ? ORDER BY e.at DESC LIMIT 50`, string(id))
	if err == nil {
		defer evtRows.Close()
		for evtRows.Next() {
			var evt EventEntry
			if err := evtRows.Scan(&evt.ID, &evt.AssetID, &evt.Type, &evt.At, &evt.Source, &evt.Detail); err != nil {
				continue
			}
			resp.RecentEvents = append(resp.RecentEvents, evt)
		}
		evtRows.Err()
	}

	return &resp, nil
}

func (q *DBQueryRepo) loadIPHistory(ctx context.Context, assetID string, version int) ([]IPHistoryEntry, error) {
	rows, err := q.db.QueryContext(ctx,
		`SELECT ip, first_seen, last_seen, is_active
		 FROM asset_ips WHERE asset_id = ? AND version = ? ORDER BY last_seen DESC`, assetID, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []IPHistoryEntry
	for rows.Next() {
		var e IPHistoryEntry
		var isActive int
		if err := rows.Scan(&e.IP, &e.FirstSeen, &e.LastSeen, &isActive); err != nil {
			return nil, err
		}
		e.Active = isActive != 0
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// --- ListEvents ---

func (q *DBQueryRepo) ListEvents(ctx context.Context, f EventFilter) (*EventListResponse, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var conditions []string
	var args []any

	if f.AssetID != "" {
		conditions = append(conditions, "e.asset_id = ?")
		args = append(args, f.AssetID)
	}
	if f.Type != "" {
		conditions = append(conditions, "e.type = ?")
		args = append(args, f.Type)
	}
	if !f.After.IsZero() {
		conditions = append(conditions, "e.at > ?")
		args = append(args, f.After.UTC().Format(time.RFC3339Nano))
	}
	if !f.Before.IsZero() {
		conditions = append(conditions, "e.at < ?")
		args = append(args, f.Before.UTC().Format(time.RFC3339Nano))
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(
		`SELECT e.id, e.asset_id, e.type, e.at, e.source, e.detail
		 FROM asset_events e %s ORDER BY e.at DESC LIMIT ?`, where,
	)
	args = append(args, limit)

	rows, err := q.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var items []EventEntry
	for rows.Next() {
		var evt EventEntry
		if err := rows.Scan(&evt.ID, &evt.AssetID, &evt.Type, &evt.At, &evt.Source, &evt.Detail); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		items = append(items, evt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &EventListResponse{Items: emptyEventSlice(items), Page: PageInfo{Limit: limit}}, nil
}

// --- ListVendors ---

func (q *DBQueryRepo) ListVendors(ctx context.Context) ([]string, error) {
	rows, err := q.db.QueryContext(ctx,
		`SELECT DISTINCT mac_vendor FROM assets
		 WHERE mac_vendor IS NOT NULL AND mac_vendor != ''
		 ORDER BY mac_vendor`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vendors []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		vendors = append(vendors, v)
	}
	return vendors, rows.Err()
}

// --- countAssetStatus: used by /api/stats ---

func (q *DBQueryRepo) CountAssetStatus(ctx context.Context) (total, online, offline int) {
	if q.db == nil {
		return 0, 0, 0
	}
	rows, err := q.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM assets GROUP BY status`)
	if err != nil {
		return 0, 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		total += count
		switch status {
		case "online":
			online = count
		case "offline":
			offline = count
		}
	}
	return total, online, offline
}

// --- helpers ---

func emptyAssetSlice(s []AssetListItem) []AssetListItem {
	if s == nil {
		return []AssetListItem{}
	}
	return s
}

func emptyEventSlice(s []EventEntry) []EventEntry {
	if s == nil {
		return []EventEntry{}
	}
	return s
}

var _ QueryRepository = (*DBQueryRepo)(nil)

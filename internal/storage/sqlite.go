package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	_ "modernc.org/sqlite"

	"passivediscovery/internal/asset"
)

type SQLiteRepo struct {
	db *sql.DB
}

func OpenSQLite(opts SQLiteOptions) (*SQLiteRepo, error) {
	if opts.Path == "" {
		return nil, errors.New("storage: database path must not be empty")
	}
	pragmas := []string{
		"foreign_keys(ON)",
		"synchronous(NORMAL)",
		fmt.Sprintf("busy_timeout(%d)", opts.BusyTimeout.Milliseconds()),
	}
	if opts.BusyTimeout <= 0 {
		pragmas[2] = "busy_timeout(5000)"
	}
	if opts.WAL {
		pragmas = append([]string{"journal_mode(WAL)"}, pragmas...)
	} else {
		pragmas = append([]string{"journal_mode(DELETE)"}, pragmas...)
	}
	dsn := opts.Path + "?_pragma=" + pragmas[0]
	for _, p := range pragmas[1:] {
		dsn += "&_pragma=" + p
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open sqlite %q: %w", opts.Path, err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: ping sqlite %q: %w", opts.Path, err)
	}
	return &SQLiteRepo{db: db}, nil
}

func (r *SQLiteRepo) Init(ctx context.Context) error {
	return initSchema(ctx, r.db)
}

func (r *SQLiteRepo) Close() error {
	return r.db.Close()
}

func (r *SQLiteRepo) DB() *sql.DB {
	return r.db
}

func (r *SQLiteRepo) SaveBatch(ctx context.Context, assets []asset.AssetSnapshot) error {
	if len(assets) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin tx: %w", err)
	}
	defer tx.Rollback()
	for _, s := range assets {
		if err := upsertAsset(ctx, tx, s); err != nil {
			return err
		}
		if err := replaceChildRows(ctx, tx, s); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepo) SaveStatistics(ctx context.Context, s Statistics) error {
	const q = `INSERT INTO statistics
		(captured_at, packets_received, assets_count, packets_per_sec)
		VALUES (?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, q,
		timeFmt(s.CapturedAt),
		s.PacketsReceived,
		s.AssetsCount,
		s.PacketsPerSec,
	)
	if err != nil {
		return fmt.Errorf("storage: save statistics: %w", err)
	}
	return nil
}

// LoadLastStatistics returns the most recent statistics row, or (zero, false, nil) when empty.
func (r *SQLiteRepo) LoadLastStatistics(ctx context.Context) (Statistics, bool, error) {
	const q = `SELECT captured_at, packets_received, assets_count, packets_per_sec
		FROM statistics ORDER BY captured_at DESC LIMIT 1`
	var s Statistics
	var capturedAtStr string
	err := r.db.QueryRowContext(ctx, q).Scan(
		&capturedAtStr,
		&s.PacketsReceived,
		&s.AssetsCount,
		&s.PacketsPerSec,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Statistics{}, false, nil
	}
	if err != nil {
		return Statistics{}, false, fmt.Errorf("storage: load last statistics: %w", err)
	}
	s.CapturedAt, _ = parseTimeStr(sql.NullString{String: capturedAtStr, Valid: true})
	return s, true, nil
}

// load assets bounded by Since (recency window) + Limit (hard cap).
func (r *SQLiteRepo) LoadAssets(ctx context.Context, opts LoadOptions) ([]asset.AssetSnapshot, error) {
	args := []any{}
	q := `SELECT id, status, mac, mac_vendor, device_type, model, os, extra_json,
	             first_seen, last_seen, seen_count
	      FROM assets`
	if !opts.Since.IsZero() {
		q += ` WHERE last_seen >= ?`
		args = append(args, timeFmt(opts.Since))
	}
	q += ` ORDER BY last_seen DESC`
	if opts.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, opts.Limit)
	}

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: load assets: %w", err)
	}
	defer rows.Close()
	var snapshots []asset.AssetSnapshot
	for rows.Next() {
		var (
			s            asset.AssetSnapshot
			extraJSON    sql.NullString
			macStr       sql.NullString
			firstSeenStr sql.NullString
			lastSeenStr  sql.NullString
			seenCount    uint64
		)
		if err := rows.Scan(
			&s.ID, &s.Status, &macStr, &s.MACVendor, &s.DeviceType, &s.Model,
			&s.OS, &extraJSON,
			&firstSeenStr, &lastSeenStr, &seenCount,
		); err != nil {
			return nil, fmt.Errorf("storage: scan asset: %w", err)
		}
		s.SeenCount = seenCount
		if macStr.Valid {
			s.MAC, _ = net.ParseMAC(macStr.String)
		}
		if extraJSON.Valid {
			_ = json.Unmarshal([]byte(extraJSON.String), &s.Extra)
		}
		s.FirstSeen, _ = parseTimeStr(firstSeenStr)
		s.LastSeen, _ = parseTimeStr(lastSeenStr)
		snapshots = append(snapshots, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range snapshots {
		id := string(snapshots[i].ID)
		var err error
		if snapshots[i].IPv4s, snapshots[i].IPv6s, err = loadIPs(ctx, r.db, id); err != nil {
			return nil, err
		}
		if snapshots[i].Hostnames, err = loadHostnames(ctx, r.db, id); err != nil {
			return nil, err
		}
		if snapshots[i].Services, err = loadServices(ctx, r.db, id); err != nil {
			return nil, err
		}
	}
	return snapshots, nil
}

func (r *SQLiteRepo) LoadAssetByMAC(ctx context.Context, macStr string) (*asset.AssetSnapshot, error) {
	if macStr == "" {
		return nil, nil
	}
	const q = `SELECT id, status, mac, mac_vendor, device_type, model, os, extra_json,
	             first_seen, last_seen, seen_count
	      FROM assets WHERE mac = ? LIMIT 1`
	var (
		s            asset.AssetSnapshot
		macCol       sql.NullString
		extraJSON    sql.NullString
		firstSeenStr sql.NullString
		lastSeenStr  sql.NullString
		seenCount    uint64
	)
	err := r.db.QueryRowContext(ctx, q, macStr).Scan(
		&s.ID, &s.Status, &macCol, &s.MACVendor, &s.DeviceType, &s.Model,
		&s.OS, &extraJSON,
		&firstSeenStr, &lastSeenStr, &seenCount,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: load asset by MAC %q: %w", macStr, err)
	}
	s.SeenCount = seenCount
	if macCol.Valid {
		s.MAC, _ = net.ParseMAC(macCol.String)
	}
	if extraJSON.Valid {
		_ = json.Unmarshal([]byte(extraJSON.String), &s.Extra)
	}
	s.FirstSeen, _ = parseTimeStr(firstSeenStr)
	s.LastSeen, _ = parseTimeStr(lastSeenStr)
	id := string(s.ID)
	var err2 error
	if s.IPv4s, s.IPv6s, err2 = loadIPs(ctx, r.db, id); err2 != nil {
		return nil, err2
	}
	if s.Hostnames, err2 = loadHostnames(ctx, r.db, id); err2 != nil {
		return nil, err2
	}
	if s.Services, err2 = loadServices(ctx, r.db, id); err2 != nil {
		return nil, err2
	}
	return &s, nil
}

func upsertAsset(ctx context.Context, tx *sql.Tx, s asset.AssetSnapshot) error {
	const q = `INSERT INTO assets
		(id, status, mac, mac_vendor, device_type, model, os, extra_json,
		 first_seen, last_seen, seen_count, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			status      = excluded.status,
			mac         = COALESCE(NULLIF(excluded.mac, ''), assets.mac),
			mac_vendor  = COALESCE(NULLIF(excluded.mac_vendor, ''), assets.mac_vendor),
			device_type = COALESCE(NULLIF(excluded.device_type, ''), assets.device_type),
			model       = COALESCE(NULLIF(excluded.model, ''), assets.model),
			os          = COALESCE(NULLIF(excluded.os, ''), assets.os),
			first_seen  = MIN(assets.first_seen, excluded.first_seen),
			last_seen   = MAX(assets.last_seen, excluded.last_seen),
			seen_count  = MAX(assets.seen_count, excluded.seen_count),
			updated_at  = excluded.updated_at`
	extraJSON := marshalExtras(s.Extra)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx, q,
		s.ID, s.Status, macStr(s.MAC), s.MACVendor, s.DeviceType, s.Model,
		s.OS, nullString(extraJSON),
		timeFmt(s.FirstSeen), timeFmt(s.LastSeen), s.SeenCount,
		now, now,
	)
	if err != nil {
		return fmt.Errorf("storage: upsert asset %s: %w", s.ID, err)
	}
	return nil
}

func replaceChildRows(ctx context.Context, tx *sql.Tx, s asset.AssetSnapshot) error {
	id := string(s.ID)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	for ip, e := range s.IPv4s {
		if err := upsertIPRow(ctx, tx, id, ip, 4, e, now); err != nil {
			return err
		}
	}
	for ip, e := range s.IPv6s {
		if err := upsertIPRow(ctx, tx, id, ip, 6, e, now); err != nil {
			return err
		}
	}

	for _, h := range s.Hostnames {
		if h == "" {
			continue
		}
		const q = `INSERT INTO asset_hostnames(asset_id, hostname, first_seen, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(asset_id, hostname) DO UPDATE SET
				last_seen = excluded.last_seen,
				updated_at = excluded.updated_at`
		if _, err := tx.ExecContext(ctx, q, id, h, timeFmt(s.FirstSeen), timeFmt(s.LastSeen), now); err != nil {
			return fmt.Errorf("storage: upsert hostname %s/%s: %w", id, h, err)
		}
	}

	for _, svc := range s.Services {
		if svc.Protocol == "" && svc.Port == 0 {
			continue
		}
		lastSeen := timeFmt(svc.LastSeen)
		if svc.LastSeen.IsZero() {
			lastSeen = timeFmt(s.LastSeen)
		}
		const q = `INSERT INTO asset_services
			(asset_id, protocol, port, name, version, product, vendor, banner,
			 is_active, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(asset_id, protocol, port) DO UPDATE SET
				name = excluded.name,
				version = excluded.version,
				product = excluded.product,
				vendor = excluded.vendor,
				banner = excluded.banner,
				is_active = excluded.is_active,
				last_seen = excluded.last_seen,
				updated_at = excluded.updated_at`
		if _, err := tx.ExecContext(ctx, q, id, svc.Protocol, svc.Port,
			svc.Name, svc.Version, svc.Product, svc.Vendor, svc.Banner,
			boolInt(svc.IsActive), lastSeen, now); err != nil {
			return fmt.Errorf("storage: upsert service %s/%s:%d: %w", id, svc.Protocol, svc.Port, err)
		}
	}
	return nil
}

func upsertIPRow(ctx context.Context, tx *sql.Tx, assetID, ip string, ver int, e asset.IPEntry, now string) error {
	const q = `INSERT INTO asset_ips
		(asset_id, ip, version, first_seen, last_seen, lease_seconds, is_active, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(asset_id, ip) DO UPDATE SET
			version = excluded.version,
			last_seen = MAX(asset_ips.last_seen, excluded.last_seen),
			first_seen = MIN(asset_ips.first_seen, excluded.first_seen),
			lease_seconds = MAX(asset_ips.lease_seconds, excluded.lease_seconds),
			is_active = excluded.is_active,
			updated_at = excluded.updated_at`
	_, err := tx.ExecContext(ctx, q,
		assetID, ip, ver,
		timeFmt(e.FirstSeen), timeFmt(e.LastSeen),
		int64(e.Lease.Seconds()), boolInt(e.IsActive), now,
	)
	if err != nil {
		return fmt.Errorf("storage: upsert IP %s/%s: %w", assetID, ip, err)
	}
	return nil
}

func loadIPs(ctx context.Context, db *sql.DB, assetID string) (ipv4s, ipv6s map[string]asset.IPEntry, err error) {
	const q = `SELECT ip, version, first_seen, last_seen, lease_seconds, is_active
		FROM asset_ips WHERE asset_id = ?`
	rows, err := db.QueryContext(ctx, q, assetID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	ipv4s = make(map[string]asset.IPEntry)
	ipv6s = make(map[string]asset.IPEntry)

	for rows.Next() {
		var (
			ip           string
			ver          int
			leaseSec     int64
			isActive     int
			firstSeenStr sql.NullString
			lastSeenStr  sql.NullString
			e            asset.IPEntry
		)
		if err := rows.Scan(&ip, &ver, &firstSeenStr, &lastSeenStr, &leaseSec, &isActive); err != nil {
			return nil, nil, err
		}
		e.FirstSeen, _ = parseTimeStr(firstSeenStr)
		e.LastSeen, _ = parseTimeStr(lastSeenStr)
		e.Lease = time.Duration(leaseSec) * time.Second
		e.IsActive = isActive != 0
		if ver == 6 {
			ipv6s[ip] = e
		} else {
			ipv4s[ip] = e
		}
	}
	return ipv4s, ipv6s, rows.Err()
}

func loadHostnames(ctx context.Context, db *sql.DB, assetID string) ([]string, error) {
	const q = `SELECT hostname FROM asset_hostnames WHERE asset_id = ?`
	rows, err := db.QueryContext(ctx, q, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hostnames []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hostnames = append(hostnames, h)
	}
	return hostnames, rows.Err()
}

func loadServices(ctx context.Context, db *sql.DB, assetID string) ([]asset.Service, error) {
	const q = `SELECT protocol, port, name, version, product, vendor, banner, is_active, last_seen
		FROM asset_services WHERE asset_id = ?`
	rows, err := db.QueryContext(ctx, q, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var svcs []asset.Service
	for rows.Next() {
		var s asset.Service
		var isActive int
		var lastSeenStr sql.NullString
		if err := rows.Scan(&s.Protocol, &s.Port, &s.Name, &s.Version,
			&s.Product, &s.Vendor, &s.Banner, &isActive, &lastSeenStr); err != nil {
			return nil, err
		}
		s.LastSeen, _ = parseTimeStr(lastSeenStr)
		s.IsActive = isActive != 0
		svcs = append(svcs, s)
	}
	return svcs, rows.Err()
}

func timeFmt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parseTimeStr(s sql.NullString) (time.Time, error) {
	if !s.Valid || s.String == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s.String)
	}
	return t, err
}

func macStr(m net.HardwareAddr) string {
	if len(m) == 0 {
		return ""
	}
	return m.String()
}

func marshalExtras(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, _ := json.Marshal(m)
	return string(b)
}

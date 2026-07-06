package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	_ "modernc.org/sqlite"

	"passivediscovery/internal/asset"
)

type SQLiteRepo struct { // implement repository
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
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: ping sqlite %q: %w", opts.Path, err)
	}
	return &SQLiteRepo{db: db}, nil
}

// init: run schema
func (r *SQLiteRepo) Init(ctx context.Context) error {
	return initSchema(ctx, r.db)
}

func (r *SQLiteRepo) Close() error {
	return r.db.Close()
}

// save batch
func (r *SQLiteRepo) SaveBatch(ctx context.Context, batch Batch) error {
	if len(batch.Assets) == 0 && len(batch.Events) == 0 { // nothing 
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil) // begin transaction
	if err != nil {
		return fmt.Errorf("storage: begin tx: %w", err)
	}
	defer tx.Rollback()
	for _, s := range batch.Assets {
		if err := upsertAsset(ctx, tx, s); err != nil {
			return err
		}
		if err := replaceChildRows(ctx, tx, s); err != nil {
			return err
		}
	}
	for _, ev := range batch.Events {
		if err := insertEvent(ctx, tx, ev, batch.RunID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// save run stats
func (r *SQLiteRepo) SaveRunStart(ctx context.Context, run CaptureRun) error {
	const q = `INSERT OR REPLACE INTO capture_runs
		(id, mode, source_name, pcap_path, interface_name, started_at, ended_at,
		 packets_received, observations, assets_created, assets_updated,
		 kernel_dropped, internal_dropped, errors)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, q,
		run.ID, run.Mode, run.SourceName, nullString(run.PCAPPath),
		nullString(run.InterfaceName), timeFmt(run.StartedAt), nullTimeStr(run.EndedAt),
		run.PacketsReceived, run.Observations, run.AssetsCreated, run.AssetsUpdated,
		run.KernelDropped, run.InternalDropped, run.Errors,
	)
	if err != nil {
		return fmt.Errorf("storage: save run start: %w", err)
	}
	return nil
}

// save run stats at end 
func (r *SQLiteRepo) SaveRunEnd(ctx context.Context, run CaptureRun) error {
	const q = `UPDATE capture_runs SET
		ended_at = ?, packets_received = ?, observations = ?,
		assets_created = ?, assets_updated = ?,
		kernel_dropped = ?, internal_dropped = ?, errors = ?
		WHERE id = ?`

	_, err := r.db.ExecContext(ctx, q,
		timeFmt(run.EndedAt),
		run.PacketsReceived, run.Observations,
		run.AssetsCreated, run.AssetsUpdated,
		run.KernelDropped, run.InternalDropped, run.Errors,
		run.ID,
	)
	if err != nil {
		return fmt.Errorf("storage: save run end: %w", err)
	}
	return nil
}

// save runtime stats
func (r *SQLiteRepo) SaveStats(ctx context.Context, snap StatsSnapshot) error {
	const q = `INSERT INTO runtime_stats
		(run_id, captured_at, packets_received, observations,
		 assets_created, assets_updated, kernel_dropped, internal_dropped,
		 raw_queue_depth, persist_queue_depth,
		 db_flush_count, db_flush_errors, db_flush_last_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, q,
		snap.RunID, timeFmt(snap.CapturedAt),
		snap.PacketsReceived, snap.Observations,
		snap.AssetsCreated, snap.AssetsUpdated,
		snap.KernelDropped, snap.InternalDropped,
		snap.RawQueueDepth, snap.PersistQueueDepth,
		snap.DBFlushCount, snap.DBFlushErrors,
		snap.DBFlushLast.Milliseconds(),
	)
	if err != nil {
		return fmt.Errorf("storage: save stats: %w", err)
	}
	return nil
}

// load assets from db
func (r *SQLiteRepo) LoadAssets(ctx context.Context) ([]asset.AssetSnapshot, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, status, mac, mac_vendor, device_type, model, os, extra_json,
		        first_seen, last_seen, seen_count
		 FROM assets ORDER BY first_seen`)
	if err != nil {
		return nil, fmt.Errorf("storage: load assets: %w", err)
	}
	defer rows.Close()
	var snapshots []asset.AssetSnapshot
	for rows.Next() {
		var (
			s         asset.AssetSnapshot
			extraJSON sql.NullString
			macStr    sql.NullString
			seenCount uint64
		)
		if err := rows.Scan(
			&s.ID, &s.Status, &macStr, &s.MACVendor, &s.DeviceType, &s.Model,
			&s.OS, &extraJSON,
			&s.FirstSeen, &s.LastSeen, &seenCount,
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
		snapshots = append(snapshots, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range snapshots {
		id := string(snapshots[i].ID)
		snapshots[i].IPv4s, snapshots[i].IPv6s, err = loadIPs(ctx, r.db, id)
		if err != nil {
			return nil, err
		}
		snapshots[i].Hostnames, err = loadHostnames(ctx, r.db, id)
		if err != nil {
			return nil, err
		}
		snapshots[i].Services, err = loadServices(ctx, r.db, id)
		if err != nil {
			return nil, err
		}
	}
	return snapshots, nil
}

func upsertAsset(ctx context.Context, tx *sql.Tx, s asset.AssetSnapshot) error {
	// cannot insert -> do update
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

	for _, tbl := range []string{"asset_ips", "asset_hostnames", "asset_services"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+tbl+" WHERE asset_id = ?", id); err != nil {
			return fmt.Errorf("storage: delete %s for %s: %w", tbl, id, err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for ip, e := range s.IPv4s {
		if err := insertIPRow(ctx, tx, id, ip, 4, e, now); err != nil {
			return err
		}
	}
	for ip, e := range s.IPv6s {
		if err := insertIPRow(ctx, tx, id, ip, 6, e, now); err != nil {
			return err
		}
	}
	for _, h := range s.Hostnames {
		if h == "" {
			continue
		}
		const q = `INSERT INTO asset_hostnames(asset_id, hostname, first_seen, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?)`
		_, err := tx.ExecContext(ctx, q, id, h, timeFmt(s.FirstSeen), timeFmt(s.LastSeen), now)
		if err != nil {
			return fmt.Errorf("storage: insert hostname %s/%s: %w", id, h, err)
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
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.ExecContext(ctx, q, id, svc.Protocol, svc.Port,
			svc.Name, svc.Version, svc.Product, svc.Vendor, svc.Banner,
			boolInt(svc.IsActive), lastSeen, now)
		if err != nil {
			return fmt.Errorf("storage: insert service %s/%s:%d: %w", id, svc.Protocol, svc.Port, err)
		}
	}
	return nil
}

func insertIPRow(ctx context.Context, tx *sql.Tx, assetID, ip string, ver int, e asset.IPEntry, now string) error {
	const q = `INSERT INTO asset_ips
		(asset_id, ip, version, first_seen, last_seen, lease_seconds, is_active, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := tx.ExecContext(ctx, q,
		assetID, ip, ver,
		timeFmt(e.FirstSeen), timeFmt(e.LastSeen),
		int64(e.Lease.Seconds()), boolInt(e.IsActive), now,
	)
	if err != nil {
		return fmt.Errorf("storage: insert IP %s/%s: %w", assetID, ip, err)
	}
	return nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, ev asset.Event, runID string) error {
	evID := deterministicEventID(ev, runID)
	const q = `INSERT OR IGNORE INTO asset_events
		(id, run_id, asset_id, type, at, source, detail, inserted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := tx.ExecContext(ctx, q,
		evID, nullString(runID), ev.AssetID, ev.Type,
		timeFmt(ev.At), ev.Source, ev.Detail,
		timeFmt(time.Now().UTC()),
	)
	if err != nil {
		return fmt.Errorf("storage: insert event %s: %w", evID, err)
	}
	return nil
}


// generate eventID by using sha256 encoding to encode event
func deterministicEventID(ev asset.Event, runID string) string {
	h := sha256.New()
	h.Write([]byte(string(ev.AssetID)))
	h.Write([]byte(ev.Type))
	h.Write([]byte(runID))
	h.Write([]byte(timeFmt(ev.At)))
	h.Write([]byte(ev.Source))
	h.Write([]byte(ev.Detail))
	sum := hex.EncodeToString(h.Sum(nil))
	if len(sum) > 16 {
		sum = sum[:16]
	}
	return fmt.Sprintf("evt:%s:%s:%s:%s", ev.AssetID, ev.Type, runID, sum)
}

// loaders 

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
			ip       string
			ver      int
			leaseSec int64
			isActive int
			e        asset.IPEntry
		)
		if err := rows.Scan(&ip, &ver, &e.FirstSeen, &e.LastSeen, &leaseSec, &isActive); err != nil {
			return nil, nil, err
		}
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
		if err := rows.Scan(&s.Protocol, &s.Port, &s.Name, &s.Version,
			&s.Product, &s.Vendor, &s.Banner, &isActive, &s.LastSeen); err != nil {
			return nil, err
		}
		s.IsActive = isActive != 0
		svcs = append(svcs, s)
	}
	return svcs, rows.Err()
}


// helper

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

func nullTimeStr(t time.Time) sql.NullString {
	if t.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339Nano), Valid: true}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
	b, _ := json.Marshal(m) // encode anything into []byte contains JSON text
	return string(b)
}
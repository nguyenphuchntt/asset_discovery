package storage

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed schema.sql
var schemaSQL string

func initSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmtExecContext("init schema", err)
	}
	if err := applyMigrations(ctx, db); err != nil {
		return fmtExecContext("apply migrations", err)
	}
	return nil
}

// applyMigrations runs versioned schema upgrades past the baseline (v1).
func applyMigrations(ctx context.Context, db *sql.DB) error {
	const schemaVersion = 3
	current, err := currentSchemaVersion(ctx, db)
	if err != nil {
		return err
	}
	if current >= schemaVersion {
		return nil
	}

	if current < 2 {
		if err := migrateAddCascadeFK(ctx, db); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx,
			`INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
			 VALUES (2, 'asset_child_fk_cascade', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`); err != nil {
			return err
		}
	}

	if current < 3 {
		if err := migrateDropAssetEvents(ctx, db); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx,
			`INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
			 VALUES (3, 'drop_asset_events', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`); err != nil {
			return err
		}
	}
	return nil
}

func currentSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	row := db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	var v int
	if err := row.Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// migrateAddCascadeFK rebuilds child tables so their FK to assets gains
// ON DELETE CASCADE. Safe for empty tables; for populated ones we round-trip
// data through a temp table of the same shape. Tables that don't exist
// (e.g. asset_events on fresh DBs) are skipped.
func migrateAddCascadeFK(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `DROP VIEW IF EXISTS current_assets`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP VIEW IF EXISTS recent_events`); err != nil {
		return err
	}

	stmts := []struct{ from, to string }{
		{
			from: `asset_ips(asset_id, ip, version, first_seen, last_seen, lease_seconds, is_active, updated_at)`,
			to: `asset_ips(asset_id, ip, version, first_seen, last_seen, lease_seconds, is_active, updated_at,
				        PRIMARY KEY (asset_id, ip),
				        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE)`,
		},
		{
			from: `asset_hostnames(asset_id, hostname, first_seen, last_seen, updated_at)`,
			to: `asset_hostnames(asset_id, hostname, first_seen, last_seen, updated_at,
				        PRIMARY KEY (asset_id, hostname),
				        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE)`,
		},
		{
			from: `asset_services(asset_id, protocol, port, name, version, product, vendor, banner, is_active, last_seen, updated_at)`,
			to: `asset_services(asset_id, protocol, port, name, version, product, vendor, banner, is_active, last_seen, updated_at,
				        PRIMARY KEY (asset_id, protocol, port),
				        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE)`,
		},
		{
			from: `asset_events(id, run_id, asset_id, type, at, source, detail, inserted_at)`,
			to: `asset_events(id, run_id, asset_id, type, at, source, detail, inserted_at,
				        PRIMARY KEY (id),
				        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE)`,
		},
	}
	for _, s := range stmts {
		tableName := s.from[:indexParen(s.from)]
		if !tableExists(ctx, db, tableName) {
			continue
		}
		if _, err := db.ExecContext(ctx, `ALTER TABLE `+tableName+` RENAME TO _mig_`+tableName); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+s.to); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO `+tableName+` SELECT * FROM _mig_`+tableName); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE _mig_`+tableName); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(ctx, `
		CREATE VIEW IF NOT EXISTS current_assets AS
			SELECT a.id, a.status, a.mac, a.mac_vendor, a.device_type, a.model, a.os,
			       a.first_seen, a.last_seen, a.seen_count,
			       group_concat(DISTINCT ip.ip) AS ips,
			       group_concat(DISTINCT h.hostname) AS hostnames
			FROM assets a
			LEFT JOIN asset_ips ip ON ip.asset_id = a.id AND ip.is_active = 1
			LEFT JOIN asset_hostnames h ON h.asset_id = a.id
			GROUP BY a.id`); err != nil {
		return err
	}
	return nil
}

func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	row := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name)
	if err := row.Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// migrateDropAssetEvents removes the asset_events table and recent_events view.
// Event audit trail is no longer retained �� assets and their child tables
// remain untouched.
func migrateDropAssetEvents(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `DROP VIEW IF EXISTS recent_events`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_asset_events_asset_time`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_asset_events_type_time`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_asset_events_time`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS asset_events`); err != nil {
		return err
	}
	return nil
}

func indexParen(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '(' {
			return i
		}
	}
	return -1
}

func fmtExecContext(op string, err error) error {
	if err == nil {
		return nil
	}
	return &schemaError{op: op, err: err}
}

type schemaError struct {
	op  string
	err error
}

func (e *schemaError) Error() string {
	return "storage: " + e.op + ": " + e.err.Error()
}

func (e *schemaError) Unwrap() error { return e.err }

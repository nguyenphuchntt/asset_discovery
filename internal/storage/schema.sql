CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    mac TEXT,
    mac_vendor TEXT,
    device_type TEXT,
    model TEXT,
    os TEXT,
    extra_json TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_ips (
    asset_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    version INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    lease_seconds INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (asset_id, ip),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS asset_hostnames (
    asset_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (asset_id, hostname),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS asset_services (
    asset_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    name TEXT,
    version TEXT,
    product TEXT,
    vendor TEXT,
    banner TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (asset_id, protocol, port),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS asset_events (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    asset_id TEXT NOT NULL,
    type TEXT NOT NULL,
    at TEXT NOT NULL,
    source TEXT NOT NULL,
    detail TEXT,
    metadata_json TEXT,
    inserted_at TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

-- Capture run bookkeeping -------------------------------------------------------

CREATE TABLE IF NOT EXISTS capture_runs (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    source_name TEXT NOT NULL,
    pcap_path TEXT,
    interface_name TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    packets_received INTEGER NOT NULL DEFAULT 0,
    observations INTEGER NOT NULL DEFAULT 0,
    assets_created INTEGER NOT NULL DEFAULT 0,
    assets_updated INTEGER NOT NULL DEFAULT 0,
    kernel_dropped INTEGER NOT NULL DEFAULT 0,
    internal_dropped INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runtime_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    packets_received INTEGER NOT NULL,
    observations INTEGER NOT NULL,
    assets_created INTEGER NOT NULL,
    assets_updated INTEGER NOT NULL,
    kernel_dropped INTEGER NOT NULL,
    internal_dropped INTEGER NOT NULL,
    raw_queue_depth INTEGER NOT NULL,
    persist_queue_depth INTEGER NOT NULL,
    db_flush_count INTEGER NOT NULL,
    db_flush_errors INTEGER NOT NULL,
    db_flush_last_ms INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES capture_runs(id)
);

-- Indexes ------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac);
CREATE INDEX IF NOT EXISTS idx_assets_vendor ON assets(mac_vendor);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_asset_ips_ip ON asset_ips(ip);
CREATE INDEX IF NOT EXISTS idx_asset_ips_active ON asset_ips(asset_id, is_active);
CREATE INDEX IF NOT EXISTS idx_asset_ips_last_seen ON asset_ips(last_seen);
CREATE INDEX IF NOT EXISTS idx_asset_hostnames_hostname ON asset_hostnames(hostname);
CREATE INDEX IF NOT EXISTS idx_asset_events_asset_time ON asset_events(asset_id, at);
CREATE INDEX IF NOT EXISTS idx_asset_events_type_time ON asset_events(type, at);
CREATE INDEX IF NOT EXISTS idx_asset_events_time ON asset_events(at);

-- Convenience views -------------------------------------------------------------

CREATE VIEW IF NOT EXISTS current_assets AS
    SELECT
        a.id,
        a.status,
        a.mac,
        a.mac_vendor,
        a.device_type,
        a.model,
        a.os,
        a.first_seen,
        a.last_seen,
        a.seen_count,
        group_concat(DISTINCT ip.ip) AS ips,
        group_concat(DISTINCT h.hostname) AS hostnames
    FROM assets a
    LEFT JOIN asset_ips ip ON ip.asset_id = a.id AND ip.is_active = 1
    LEFT JOIN asset_hostnames h ON h.asset_id = a.id
    GROUP BY a.id;

CREATE VIEW IF NOT EXISTS recent_events AS
    SELECT
        e.at,
        e.type,
        e.asset_id,
        a.mac,
        a.mac_vendor,
        e.source,
        e.detail
    FROM asset_events e
    LEFT JOIN assets a ON a.id = e.asset_id;

-- Mark this schema as applied ---------------------------------------------------

INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
    VALUES (1, 'initial_persistence_schema', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
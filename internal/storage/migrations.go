// migrations.go will own SQLite schema creation and migration order.
//
// Expected tables:
// - assets;
// - asset_ips;
// - events;
// - stats_snapshots;
// - observations if audit/debug persistence is enabled.
package storage

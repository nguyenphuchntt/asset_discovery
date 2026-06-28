// snapshot.go will define read-only views of assets for API, CLI output, and
// persistence.
//
// Snapshot types should avoid exposing mutable internal maps/slices from
// AssetManager. They should include enough data for list/detail responses:
// identifiers, IP history, hostname, vendor hints, sources, first/last seen,
// status, and recent events.
package asset

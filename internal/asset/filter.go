// filter.go will define query filters for snapshots, storage, and API.
//
// Filters should cover status, source/protocol, vendor, hostname, seen time
// range, pagination limit/offset, and sort order. Keep filter definitions in
// the domain package so storage and API share one contract.
package asset

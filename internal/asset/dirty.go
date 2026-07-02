// dirty.go will track assets and events that need persistence.
//
// The manager can mark assets dirty after upsert/lifecycle changes. The
// persister can then request dirty snapshots in batches without scanning the
// whole asset table on every flush.
package asset

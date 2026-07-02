// Package lifecycle will determine online/offline state from passive evidence.
//
// It should not inspect raw packets. It should read asset LastSeen values or
// manager snapshots and emit status transition requests/events when an asset is
// older than the configured offline threshold.
package lifecycle

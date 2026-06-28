// Package storage will provide durable persistence for discovered assets,
// historical IPs, events, observations if enabled, and runtime stats snapshots.
//
// The default implementation should be SQLite for local demo and Docker volume
// persistence. Interfaces should stay small so tests can use fakes.
package storage

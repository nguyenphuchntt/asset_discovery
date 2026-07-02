// Package persist will bridge AssetManager dirty state to storage.Repository.
//
// It should batch writes and keep persistence latency out of the packet hot
// path. The package should not decide merge policy; it only flushes snapshots,
// events, and stats supplied by domain/runtime packages.
package persist

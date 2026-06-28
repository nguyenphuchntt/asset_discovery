// Package stats will collect runtime counters and expose immutable snapshots.
//
// Stats should cover capture, decode, analyzer, asset manager, lifecycle,
// persistence, API, and error counters. It should be safe to update from
// multiple goroutines or have a single-writer design documented clearly.
package stats

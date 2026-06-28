// Package pipeline will own the end-to-end passive discovery runtime.
//
// This package should be the composition layer between capture, decode,
// analyzer, asset manager, lifecycle, persister, stats, and API. It should not
// contain protocol parsing or merge policy itself; it should wire already
// defined interfaces together and manage process lifecycle.
package pipeline

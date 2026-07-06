package output

import (
	"context"

	"passivediscovery/internal/asset"
)

// Sink receives the final output of a discovery run. Implementations should
// treat WriteAssets / WriteEvents as idempotent for a given (snapshots, events)
// pair so retries are safe.
type Sink interface {
	// WriteAssets persists the full asset state at end-of-run.
	WriteAssets(ctx context.Context, snapshots []asset.AssetSnapshot) error
	// WriteEvents persists the append-only event log.
	WriteEvents(ctx context.Context, events []asset.Event) error
}
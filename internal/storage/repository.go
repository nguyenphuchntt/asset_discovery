package storage

import (
	"context"

	"passivediscovery/internal/asset"
)

type Repository interface {
	Init(ctx context.Context) error // create tables and run migrations
	LoadAssets(ctx context.Context) ([]asset.AssetSnapshot, error) // load assets from DB into memory on startup
	SaveBatch(ctx context.Context, batch Batch) error // upsert assets + events
	SaveRunStart(ctx context.Context, run CaptureRun) error // record a new capture run (started_at, mode, source)
	SaveRunEnd(ctx context.Context, run CaptureRun) error // finalize a capture run (ended_at, reason, packet counts)
	SaveStats(ctx context.Context, snapshot StatsSnapshot) error // persist stats snapshots
	Close() error // close DB connection
}

type Batch struct {
	RunID  string
	Assets []asset.AssetSnapshot
	Events []asset.Event
}

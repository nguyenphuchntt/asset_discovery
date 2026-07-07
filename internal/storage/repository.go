package storage

import (
	"context"

	"passivediscovery/internal/asset"
)

type Repository interface {
	Init(ctx context.Context) error
	LoadAssets(ctx context.Context, opts LoadOptions) ([]asset.AssetSnapshot, error)
	LoadAssetByMAC(ctx context.Context, mac string) (*asset.AssetSnapshot, error)
	SaveBatch(ctx context.Context, batch Batch) error
	SaveRunStart(ctx context.Context, run CaptureRun) error
	SaveRunEnd(ctx context.Context, run CaptureRun) error
	SaveStats(ctx context.Context, snapshot StatsSnapshot) error
	Close() error
}

type Batch struct {
	RunID  string
	Assets []asset.AssetSnapshot
}

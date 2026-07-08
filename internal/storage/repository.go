package storage

import (
	"context"

	"passivediscovery/internal/asset"
)

type Repository interface {
	Init(ctx context.Context) error
	LoadAssets(ctx context.Context, opts LoadOptions) ([]asset.AssetSnapshot, error)
	LoadAssetByMAC(ctx context.Context, mac string) (*asset.AssetSnapshot, error)
	LoadLastStatistics(ctx context.Context) (Statistics, bool, error)
	SaveBatch(ctx context.Context, batch []asset.AssetSnapshot) error
	SaveStatistics(ctx context.Context, s Statistics) error
	Close() error
}

type Batch struct {
	Assets []asset.AssetSnapshot
}

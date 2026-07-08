package persist

import (
	"time"

	"passivediscovery/internal/asset"
)

type Options struct {
	BatchSize    int
	FlushEvery   time.Duration
	FlushTimeout time.Duration
	RetryLimit   int
	RetryBackoff time.Duration
}

func defaultOptions() Options {
	return Options{
		BatchSize:    500,
		FlushEvery:   5 * time.Second,
		FlushTimeout: 10 * time.Second,
		RetryLimit:   3,
		RetryBackoff: 250 * time.Millisecond,
	}
}

type pendingBatch struct {
	Assets []asset.AssetSnapshot
}

func (b pendingBatch) empty() bool {
	return len(b.Assets) == 0
}

package persist

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/storage"
)

type Source interface {
	DrainDirty() []asset.AssetSnapshot
}

type Persister struct {
	repo   storage.Repository
	source Source
	opts   Options
	logger *slog.Logger

	runID string

	mu     sync.Mutex
	latest pendingBatch

	flushCount   atomic.Uint64
	flushErrors  atomic.Uint64
	lastFlushDur atomic.Int64 // nanoseconds
}

func New(repo storage.Repository, source Source, runID string, logger *slog.Logger) *Persister {
	if logger == nil {
		logger = slog.Default()
	}
	return &Persister{
		repo:   repo,
		source: source,
		runID:  runID,
		logger: logger.With(slog.String("component", "persist")),
		opts:   defaultOptions(),
	}
}

func (p *Persister) WithOptions(o Options) *Persister {
	d := defaultOptions()
	if o.BatchSize > 0 {
		d.BatchSize = o.BatchSize
	}
	if o.FlushEvery > 0 {
		d.FlushEvery = o.FlushEvery
	}
	if o.FlushTimeout > 0 {
		d.FlushTimeout = o.FlushTimeout
	}
	if o.RetryLimit > 0 {
		d.RetryLimit = o.RetryLimit
	}
	if o.RetryBackoff > 0 {
		d.RetryBackoff = o.RetryBackoff
	}
	p.opts = d
	return p
}

func (p *Persister) SetOptions(o Options) *Persister {
	d := defaultOptions()
	if o.BatchSize > 0 {
		d.BatchSize = o.BatchSize
	}
	if o.FlushEvery > 0 {
		d.FlushEvery = o.FlushEvery
	}
	if o.FlushTimeout > 0 {
		d.FlushTimeout = o.FlushTimeout
	}
	if o.RetryLimit > 0 {
		d.RetryLimit = o.RetryLimit
	}
	if o.RetryBackoff > 0 {
		d.RetryBackoff = o.RetryBackoff
	}
	p.opts = d
	return p
}

func (p *Persister) Run(ctx context.Context) error {
	p.logger.Info("persister started",
		slog.Int("batch_size", p.opts.BatchSize),
		slog.Duration("flush_every", p.opts.FlushEvery),
		slog.Duration("flush_timeout", p.opts.FlushTimeout),
	)
	ticker := time.NewTicker(p.opts.FlushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("persister received shutdown, final flush")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), p.opts.FlushTimeout)
			defer cancel()
			if err := p.Flush(shutdownCtx); err != nil {
				p.logger.Error("final flush failed", slog.String("err", err.Error()))
				return err
			}
			return nil
		case <-ticker.C:
			if err := p.Flush(ctx); err != nil {
				continue
			}
		}
	}
}

func (p *Persister) Flush(ctx context.Context) error {
	start := time.Now()

	batch, err := p.collectBatch(ctx)
	if err != nil {
		return err
	}
	if batch.empty() {
		return nil
	}

	saveCtx, cancel := context.WithTimeout(ctx, p.opts.FlushTimeout)
	defer cancel()

	if err := p.saveWithRetry(saveCtx, batch); err != nil {
		p.flushErrors.Add(1)
		p.logger.Error("persist flush ultimately failed, batch dropped",
			slog.Int("assets", len(batch.Assets)),
			slog.String("err", err.Error()),
		)
		return err
	}

	p.flushCount.Add(1)
	dur := time.Since(start)
	p.lastFlushDur.Store(int64(dur))
	p.logger.Info("persist flush completed",
		slog.Int("flush_assets", len(batch.Assets)),
		slog.Int64("flush_duration_ms", dur.Milliseconds()),
		slog.Uint64("db_flush_count", p.flushCount.Load()),
		slog.Uint64("db_flush_errors", p.flushErrors.Load()),
	)
	return nil
}

func (p *Persister) collectBatch(_ context.Context) (pendingBatch, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev := p.latest
	p.latest = pendingBatch{}

	assets := append(prev.Assets, p.source.DrainDirty()...)

	if p.opts.BatchSize > 0 && len(assets) > p.opts.BatchSize {
		overflow := assets[p.opts.BatchSize:]
		assets = assets[:p.opts.BatchSize]
		p.latest.Assets = overflow
	}

	return pendingBatch{Assets: assets}, nil
}

func (p *Persister) saveWithRetry(ctx context.Context, batch pendingBatch) error {
	var last error
	backoff := p.opts.RetryBackoff
	if backoff <= 0 {
		backoff = 100 * time.Millisecond
	}
	max := p.opts.RetryLimit
	if max <= 0 {
		max = 1
	}
	for attempt := 0; attempt < max; attempt++ {
		err := p.repo.SaveBatch(ctx, storage.Batch{
			RunID:  p.runID,
			Assets: batch.Assets,
		})
		if err == nil {
			return nil
		}
		last = err
		if errors.Is(err, context.Canceled) {
			return err
		}
		p.logger.Warn("persist flush failed, will retry",
			slog.Int("attempt", attempt+1),
			slog.Int("max", max),
			slog.String("err", err.Error()),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
	if last == nil {
		last = fmt.Errorf("persist: unknown error")
	}
	return last
}

func (p *Persister) Counters() (flushCount, flushErrors uint64, lastFlush time.Duration) {
	return p.flushCount.Load(), p.flushErrors.Load(), time.Duration(p.lastFlushDur.Load())
}

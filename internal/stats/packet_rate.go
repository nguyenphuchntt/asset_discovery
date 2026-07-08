package stats

import (
	"context"
	"sync"
	"time"
)

// PacketRate calculates packets-per-second using a rolling window ring buffer.
type PacketRate struct {
	mu       sync.Mutex
	buckets  []uint64
	size     int
	cur      int
	total    uint64
	interval time.Duration
}

// NewPacketRate creates a ring buffer with `size` buckets, each representing
// `interval` of time. Defaults: size=60, interval=1s (=> 60s window).
func NewPacketRate(interval time.Duration, size int) *PacketRate {
	if size <= 0 {
		size = 60
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &PacketRate{
		buckets:  make([]uint64, size),
		size:     size,
		interval: interval,
	}
}

// Inc increments the current bucket counter.
func (p *PacketRate) Inc() {
	p.mu.Lock()
	p.buckets[p.cur]++
	p.total++
	p.mu.Unlock()
}

// Rate returns the average packets per second over the rolling window.
func (p *PacketRate) Rate() float64 {
	p.mu.Lock()
	t := p.total
	p.mu.Unlock()
	return float64(t) / float64(p.size)
}

// Run rotates buckets every interval. Blocks until ctx is done.
func (p *PacketRate) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.rotate()
		}
	}
}

func (p *PacketRate) rotate() {
	p.mu.Lock()
	p.total -= p.buckets[p.cur]
	p.buckets[p.cur] = 0
	p.cur = (p.cur + 1) % p.size
	p.mu.Unlock()
}
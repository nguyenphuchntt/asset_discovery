package pipeline

import "sync/atomic"

type Counters struct {
	processed atomic.Int64
	applied   atomic.Int64
	dropped   atomic.Int64
}

func (c *Counters) AddProcessed(n int) { c.processed.Add(int64(n)) }
func (c *Counters) AddApplied(n int)   { c.applied.Add(int64(n)) }
func (c *Counters) AddDropped(n int)   { c.dropped.Add(int64(n)) }

func (c *Counters) Snapshot() (processed, applied, dropped int) {
	return int(c.processed.Load()), int(c.applied.Load()), int(c.dropped.Load())
}
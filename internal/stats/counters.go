package stats

import "time"

type Counters struct {
	PacketsReceived uint64        `json:"packets_received"` // struct tag -> when convert to JSON
	Observations    uint64        `json:"observations"`
	AssetsCreated   uint64        `json:"assets_created"`
	AssetsUpdated   uint64        `json:"assets_updated"`
	KernelDropped   uint64        `json:"kernel_dropped"`
	InternalDropped uint64        `json:"internal_dropped"`
	DBFlushCount    uint64        `json:"db_flush_count"`
	DBFlushErrors   uint64        `json:"db_flush_errors"`
	DBFlushLast     time.Duration `json:"db_flush_last"`
}

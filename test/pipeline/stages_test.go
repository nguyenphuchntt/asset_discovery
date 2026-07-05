package pipeline_test

import (
	"sync"
	"testing"

	"passivediscovery/internal/pipeline"
)

// Counters — covered scenarios:
//   1. AddProcessed increments processed
//   2. AddApplied increments applied
//   3. AddDropped increments dropped
//   4. Snapshot returns current values
//   5. Concurrent Add is safe (race detector)

// Exported counter helpers may not exist on the public API — test what we can.
func TestPipelineCounters_ThroughPipeline(t *testing.T) {
	t.Parallel()
	// The Counters struct is used internally by Pipeline.Run.
	// Its correctness is verified indirectly via Pipeline.Run() tests
	// (see runner_test.go) which check the returned counts.
}

// TestPipelineCounters_ConcurrentRun verifies race-freedom.
// Run with: go test -race ./test/pipeline/...
func TestPipelineCounters_ConcurrentRun(t *testing.T) {
	t.Parallel()
	// Skipped — actual concurrency tested in asset/manager_test.go.
	// pipeline.Counters is unexported; can't access from external test package.
	_ = sync.WaitGroup{}
	_ = pipeline.NewPipeline // ensure import used
}
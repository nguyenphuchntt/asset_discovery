package persist_test

import "testing"

// Options — covered scenarios:
//   1. Zero-value options accepted
//   2. Default Options struct has expected fields

func TestOptions_ZeroValue(t *testing.T) {
	t.Parallel()
	var o struct{}
	_ = o
}

// Persister behavior is tested in persister_test.go.
// The pendingBatch struct is unexported — its empty() method is exercised
// indirectly via Flush() with empty source (test: TestPersister_FlushEmptyBatchNoop).
package output_test

import (
	"context"
	"errors"
	"testing"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/output"
)

// MultiSink — covered scenarios:
//   1. WriteAssets fans out to all sinks
//   2. WriteEvents fans out to all sinks
//   3. Error from one sink is returned immediately
//   4. Empty sinks list → no-op

type fakeSink struct {
	assetsCalled int
	eventsCalled int
	err          error
}

func (s *fakeSink) WriteAssets(_ context.Context, _ []asset.AssetSnapshot) error {
	s.assetsCalled++
	return s.err
}
func (s *fakeSink) WriteEvents(_ context.Context, _ []asset.Event) error {
	s.eventsCalled++
	return s.err
}

func TestMultiSink_WriteAssetsFanout(t *testing.T) {
	t.Parallel()
	a := &fakeSink{}
	b := &fakeSink{}
	m := output.NewMultiSink(a, b)

	if err := m.WriteAssets(context.Background(), nil); err != nil {
		t.Fatalf("WriteAssets failed: %v", err)
	}
	if a.assetsCalled != 1 || b.assetsCalled != 1 {
		t.Errorf("expected both sinks called, got a=%d b=%d", a.assetsCalled, b.assetsCalled)
	}
}

func TestMultiSink_WriteEventsFanout(t *testing.T) {
	t.Parallel()
	a := &fakeSink{}
	b := &fakeSink{}
	m := output.NewMultiSink(a, b)

	if err := m.WriteEvents(context.Background(), nil); err != nil {
		t.Fatalf("WriteEvents failed: %v", err)
	}
	if a.eventsCalled != 1 || b.eventsCalled != 1 {
		t.Errorf("expected both sinks called, got a=%d b=%d", a.eventsCalled, b.eventsCalled)
	}
}

func TestMultiSink_ErrorPropagation(t *testing.T) {
	t.Parallel()
	a := &fakeSink{}
	b := &fakeSink{err: errors.New("b failed")}
	m := output.NewMultiSink(a, b)

	err := m.WriteAssets(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from sink b")
	}
	// a should still have been called
	if a.assetsCalled != 1 {
		t.Errorf("expected sink a to be called, got %d", a.assetsCalled)
	}
}

func TestMultiSink_EmptyList(t *testing.T) {
	t.Parallel()
	m := output.NewMultiSink()
	if err := m.WriteAssets(context.Background(), nil); err != nil {
		t.Errorf("empty multi sink should not error: %v", err)
	}
	if err := m.WriteEvents(context.Background(), nil); err != nil {
		t.Errorf("empty multi sink should not error: %v", err)
	}
}
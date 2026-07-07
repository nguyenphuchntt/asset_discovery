package output_test

import (
	"context"
	"errors"
	"testing"

	"passivediscovery/internal/asset"
	"passivediscovery/internal/output"
)

type fakeSink struct {
	assetsCalled int
	err          error
}

func (s *fakeSink) WriteAssets(_ context.Context, _ []asset.AssetSnapshot) error {
	s.assetsCalled++
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

func TestMultiSink_ErrorPropagation(t *testing.T) {
	t.Parallel()
	a := &fakeSink{}
	b := &fakeSink{err: errors.New("b failed")}
	m := output.NewMultiSink(a, b)

	err := m.WriteAssets(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from sink b")
	}
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
}

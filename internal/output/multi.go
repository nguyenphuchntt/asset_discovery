package output

import (
	"context"

	"passivediscovery/internal/asset"
)

type MultiSink struct {
	sinks []Sink
}

func NewMultiSink(sinks ...Sink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (m *MultiSink) WriteAssets(ctx context.Context, snapshots []asset.AssetSnapshot) error {
	for _, s := range m.sinks {
		if err := s.WriteAssets(ctx, snapshots); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiSink) WriteEvents(ctx context.Context, events []asset.Event) error {
	for _, s := range m.sinks {
		if err := s.WriteEvents(ctx, events); err != nil {
			return err
		}
	}
	return nil
}
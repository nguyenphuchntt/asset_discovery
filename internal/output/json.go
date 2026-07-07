package output

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"passivediscovery/internal/asset"
)

type JSONSink struct {
	dir    string
	stamp  string
	logger *slog.Logger
}

func NewJSONSink(dir string, logger *slog.Logger) *JSONSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &JSONSink{
		dir:    dir,
		stamp:  time.Now().UTC().Format("20060102T150405Z"),
		logger: logger.With(slog.String("component", "output.json")),
	}
}

func (s *JSONSink) AssetsPath() string {
	return filepath.Join(s.dir, "discovery-"+s.stamp+".assets.json")
}

func (s *JSONSink) WriteAssets(_ context.Context, snapshots []asset.AssetSnapshot) error {
	if err := writeJSONFile(s.AssetsPath(), snapshots); err != nil {
		return fmt.Errorf("output: write assets: %w", err)
	}
	s.logger.Info("wrote asset snapshot",
		slog.String("path", s.AssetsPath()),
		slog.Int("count", len(snapshots)),
	)
	return nil
}

func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

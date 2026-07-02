// log.go owns logger construction for the service.
//
// Long-term responsibilities:
// - configure slog level and output destination;
// - keep logs structured enough for demo and troubleshooting;
// - avoid mixing logging policy into packet processing packages;
// - later support JSON/text mode if deployment needs it.
package log

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func NewLogger(level string) (*slog.Logger, error) {
	level = strings.ToLower(strings.TrimSpace(level))

	slogLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	})

	return slog.New(handler), nil
}

func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid --log-level %q", level)
	}
}

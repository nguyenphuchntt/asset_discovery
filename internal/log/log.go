package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Options struct {
	Level  string // debug|info|warn|error
	Format string // text|json
	Output string // stdout|stderr|<path>
}

func NewLogger(opts Options) (*slog.Logger, io.Closer, error) {
	level := strings.ToLower(strings.TrimSpace(opts.Level))
	if level == "" {
		level = "info"
	}
	slogLevel, err := parseLevel(level)
	if err != nil {
		return nil, nil, fmt.Errorf("log: %w", err)
	}

	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return nil, nil, fmt.Errorf("log: invalid format %q (text|json)", opts.Format)
	}

	out, closer, err := openOutput(opts.Output)
	if err != nil {
		return nil, nil, err
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slogLevel})
	} else {
		handler = slog.NewTextHandler(out, &slog.HandlerOptions{Level: slogLevel})
	}

	logger := slog.New(handler).With(slog.String("service", "passivediscovery"))
	return logger, closer, nil
}

func openOutput(output string) (io.Writer, io.Closer, error) {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "", "stdout":
		return os.Stdout, noopCloser{}, nil
	case "stderr":
		return os.Stderr, noopCloser{}, nil
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("log: open output %q: %w", output, err)
		}
		return f, f, nil
	}
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

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

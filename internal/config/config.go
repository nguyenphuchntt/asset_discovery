package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	ModePCAP Mode = "pcap"
	ModeLive Mode = "live"
)

const (
	DefaultLogLevel    = "info"
	DefaultOfflineAfter = 5 * time.Minute
	DefaultQueueSize   = 4096
	DefaultWorkers     = 1
	DefaultFlushEvery  = 5 * time.Second
	DefaultBatchSize   = 500
)

var ErrHelp = flag.ErrHelp

type Config struct {
	Mode Mode
 
	PCAPPath  string
	Interface string
 
	BPF string
 
	OutputDirectory string
 
	LogLevel string
 
	OfflineAfter time.Duration
	QueueSize    int
	Workers      int
	FlushEvery   time.Duration
	BatchSize    int
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func applyEnvDefaults(cfg *Config, getenv func(string) string) error {
	if cfg == nil || getenv == nil {
		return nil
	}
 
	cfg.PCAPPath = firstNonEmpty(getenv("DISCOVERY_PCAP"), cfg.PCAPPath)
	cfg.Interface = firstNonEmpty(getenv("DISCOVERY_INTERFACE"), cfg.Interface)
	cfg.BPF = firstNonEmpty(getenv("DISCOVERY_BPF"), cfg.BPF)
	cfg.OutputDirectory = firstNonEmpty(getenv("DISCOVERY_OUTPUT"), cfg.OutputDirectory)
	cfg.LogLevel = firstNonEmpty(getenv("DISCOVERY_LOG_LEVEL"), cfg.LogLevel)
 
	if value := strings.TrimSpace(getenv("DISCOVERY_OFFLINE_AFTER")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_OFFLINE_AFTER %q: %w", value, err)
		}
		cfg.OfflineAfter = d
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_FLUSH_EVERY")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_FLUSH_EVERY %q: %w", value, err)
		}
		cfg.FlushEvery = d
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_QUEUE_SIZE")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_QUEUE_SIZE %q: %w", value, err)
		}
		cfg.QueueSize = n
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_WORKERS")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_WORKERS %q: %w", value, err)
		}
		cfg.Workers = n
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_BATCH_SIZE")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_BATCH_SIZE %q: %w", value, err)
		}
		cfg.BatchSize = n
	}
 
	return nil
}

func Parse(args []string, getenv func(string) string) (*Config, error) {
	cfg := &Config{
		LogLevel:     DefaultLogLevel,
		OfflineAfter: DefaultOfflineAfter,
		QueueSize:    DefaultQueueSize,
		Workers:      DefaultWorkers,
		FlushEvery:   DefaultFlushEvery,
		BatchSize:    DefaultBatchSize,
	}
 
	if err := applyEnvDefaults(cfg, getenv); err != nil {
		return nil, err
	}
 
	fs := flag.NewFlagSet("discovery", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress default flag error output; we return errors ourselves
 
	fs.StringVar(&cfg.PCAPPath, "pcap", cfg.PCAPPath, "absolute path to input PCAP file")
	fs.StringVar(&cfg.Interface, "interface", cfg.Interface, "network interface for live capture")
	fs.StringVar(&cfg.BPF, "bpf", cfg.BPF, "BPF filter for packet capture (empty = capture all)")
	fs.StringVar(&cfg.OutputDirectory, "output", cfg.OutputDirectory, "directory for JSON output files (must exist)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, error")
	fs.DurationVar(&cfg.OfflineAfter, "offline-after", cfg.OfflineAfter, "asset offline threshold duration")
	fs.IntVar(&cfg.QueueSize, "queue-size", cfg.QueueSize, "packet queue size")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "packet processing workers")
	fs.DurationVar(&cfg.FlushEvery, "flush-every", cfg.FlushEvery, "database flush interval")
	fs.IntVar(&cfg.BatchSize, "batch-size", cfg.BatchSize, "database batch size")
 
	if err := fs.Parse(args); err != nil {
		// Preserve ErrHelp so callers can print usage without treating it as a failure.
		if errors.Is(err, flag.ErrHelp) {
			return nil, ErrHelp
		}
		return nil, err
	}
 
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
 
	return cfg, nil
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
 
	c.PCAPPath = strings.TrimSpace(c.PCAPPath)
	c.Interface = strings.TrimSpace(c.Interface)
	c.BPF = strings.TrimSpace(c.BPF)
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	c.OutputDirectory = strings.TrimSpace(c.OutputDirectory)
 
	hasPCAP := c.PCAPPath != ""
	hasInterface := c.Interface != ""
	switch {
	case hasPCAP && hasInterface:
		return errors.New("--pcap and --interface are mutually exclusive; provide exactly one")
	case !hasPCAP && !hasInterface:
		return errors.New("one of --pcap or --interface is required")
	case hasPCAP:
		c.Mode = ModePCAP
	case hasInterface:
		c.Mode = ModeLive
	}
 
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid --log-level %q: must be debug, info, warn, or error", c.LogLevel)
	}

	if c.OutputDirectory == "" {
		return errors.New("--output is required")
	}
	if info, err := os.Stat(c.OutputDirectory); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("--output directory %q does not exist", c.OutputDirectory)
		}
		return fmt.Errorf("--output directory %q: %w", c.OutputDirectory, err)
	} else if !info.IsDir() {
		return fmt.Errorf("--output %q is not a directory", c.OutputDirectory)
	}
 
	if c.OfflineAfter <= 0 {
		return errors.New("--offline-after must be greater than zero")
	}
	if c.QueueSize <= 0 {
		return errors.New("--queue-size must be greater than zero")
	}
	if c.Workers <= 0 {
		return errors.New("--workers must be greater than zero")
	}
	if c.FlushEvery <= 0 {
		return errors.New("--flush-every must be greater than zero")
	}
	if c.BatchSize <= 0 {
		return errors.New("--batch-size must be greater than zero")
	}

	return nil
}

func Usage() string {
	return `Usage:
  discovery --pcap <file>      --output <dir> [flags]
  discovery --interface <name> --output <dir> [flags]
 
Capture source:
  --pcap        Path to input PCAP file.
  --interface   Network interface for live capture.
 
Output:
  --output      Directory for JSON result files (must already exist).
 
Capture options:
  --bpf         BPF filter expression. Default: empty (capture all packets).
 
Processing options:
  --offline-after   Asset offline threshold duration. Default: 5m.
  --queue-size      Packet queue size. Default: 4096.
  --workers         Packet processing workers. Default: 1.
  --flush-every     Flush interval for writing results. Default: 5s.
  --batch-size      Batch size for writing results. Default: 500.
 
Logging:
  --log-level   Log level: debug, info, warn, error. Default: info.
 
Environment variable:
  DISCOVERY_PCAP, DISCOVERY_INTERFACE, DISCOVERY_OUTPUT,
  DISCOVERY_BPF, DISCOVERY_OFFLINE_AFTER, DISCOVERY_LOG_LEVEL,
  DISCOVERY_QUEUE_SIZE, DISCOVERY_WORKERS, DISCOVERY_FLUSH_EVERY,
  DISCOVERY_BATCH_SIZE
`
}
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
	DefaultLogLevel       = "info"
	DefaultOutputDir      = "./output"
	DefaultDBPath         = "./output/discovery.db"
	DefaultLogPath        = "./output/discovery.log"
	DefaultOfflineAfter   = 5 * time.Minute
	DefaultQueueSize      = 4096
	DefaultWorkers        = 1
	DefaultFlushEvery     = 5 * time.Second
	DefaultBatchSize      = 500
	DefaultLoadLimit      = 1000
	DefaultLoadWindow     = 24 * time.Hour
	DefaultUIRefresh      = 5 * time.Second
	DefaultAPIReadTimeout = 5 * time.Second
)

const (
	IpGrace = 5 * time.Minute
)


var ErrHelp = flag.ErrHelp

type Config struct {
	Mode Mode

	PCAPPath  string
	Interface string

	BPF string

	OutputDirectory string
	OUIPath         string

	LogLevel  string
	LogFormat string // text|json
	LogOutput string // stdout|<path>

	OfflineAfter time.Duration
	QueueSize    int
	Workers      int
	FlushEvery   time.Duration
	BatchSize    int

	DBPath        string
	DBWAL         bool
	DBBusyTimeout time.Duration
	KeepJSONOutput bool

	LoadLimit  int           // max assets loaded at startup (0 = unlimited, default 1000)
	LoadWindow time.Duration // only load assets seen within this window (default 24h)
	EvictAfter time.Duration // evict offline assets after this; 0 = 7×LoadWindow

	// API / Dashboard
	APIAddr        string        // bind address for HTTP server (empty = disabled)
	UIEnabled      bool          // serve embedded dashboard at /
	UIRefreshEvery time.Duration // dashboard polling interval (default 5s)
	APIReadTimeout time.Duration // server read timeout (default 5s)
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
	cfg.OUIPath = firstNonEmpty(getenv("DISCOVERY_OUI"), cfg.OUIPath)
	cfg.LogLevel = firstNonEmpty(getenv("DISCOVERY_LOG_LEVEL"), cfg.LogLevel)
	cfg.LogFormat = firstNonEmpty(getenv("DISCOVERY_LOG_FORMAT"), cfg.LogFormat)
	cfg.LogOutput = firstNonEmpty(getenv("DISCOVERY_LOG_OUTPUT"), cfg.LogOutput)
	cfg.DBPath = firstNonEmpty(getenv("DISCOVERY_DB"), cfg.DBPath)
	if v := strings.ToLower(strings.TrimSpace(getenv("DISCOVERY_DB_WAL"))); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			cfg.DBWAL = true
		case "0", "false", "no", "off":
			cfg.DBWAL = false
		}
	}
	if v := strings.ToLower(strings.TrimSpace(getenv("DISCOVERY_KEEP_JSON_OUTPUT"))); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			cfg.KeepJSONOutput = true
		case "0", "false", "no", "off":
			cfg.KeepJSONOutput = false
		}
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_DB_BUSY_TIMEOUT")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_DB_BUSY_TIMEOUT %q: %w", value, err)
		}
		cfg.DBBusyTimeout = d
	}

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

	if value := strings.TrimSpace(getenv("DISCOVERY_LOAD_LIMIT")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_LOAD_LIMIT %q: %w", value, err)
		}
		if n < 0 {
			return fmt.Errorf("invalid DISCOVERY_LOAD_LIMIT %q: must be >= 0", value)
		}
		cfg.LoadLimit = n
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_LOAD_WINDOW")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_LOAD_WINDOW %q: %w", value, err)
		}
		cfg.LoadWindow = d
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_EVICT_AFTER")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_EVICT_AFTER %q: %w", value, err)
		}
		if d < 0 {
			return fmt.Errorf("invalid DISCOVERY_EVICT_AFTER %q: must be >= 0", value)
		}
		cfg.EvictAfter = d
	}

	cfg.APIAddr = firstNonEmpty(getenv("DISCOVERY_API_ADDR"), cfg.APIAddr)
	if v := strings.ToLower(strings.TrimSpace(getenv("DISCOVERY_UI"))); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			cfg.UIEnabled = true
		case "0", "false", "no", "off":
			cfg.UIEnabled = false
		}
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_UI_REFRESH_EVERY")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_UI_REFRESH_EVERY %q: %w", value, err)
		}
		cfg.UIRefreshEvery = d
	}
	if value := strings.TrimSpace(getenv("DISCOVERY_API_READ_TIMEOUT")); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DISCOVERY_API_READ_TIMEOUT %q: %w", value, err)
		}
		cfg.APIReadTimeout = d
	}

	return nil
}

func Parse(args []string, getenv func(string) string) (*Config, error) {
	cfg := &Config{
		LogLevel:       DefaultLogLevel,
		LogFormat:      "text",
		LogOutput:      DefaultLogPath,
		OutputDirectory: DefaultOutputDir,
		DBPath:         DefaultDBPath,
		DBWAL:          true,
		DBBusyTimeout:  5 * time.Second,
		OfflineAfter:   DefaultOfflineAfter,
		QueueSize:      DefaultQueueSize,
		Workers:        DefaultWorkers,
		FlushEvery:     DefaultFlushEvery,
		BatchSize:      DefaultBatchSize,
		LoadLimit:      DefaultLoadLimit,
		LoadWindow:     DefaultLoadWindow,
		EvictAfter:     0, // 0 = derive 7×LoadWindow at startup
		UIRefreshEvery: DefaultUIRefresh,
		APIReadTimeout: DefaultAPIReadTimeout,
	}

	if err := applyEnvDefaults(cfg, getenv); err != nil {
		return nil, err
	}

	fs := flag.NewFlagSet("discovery", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress default flag error output; we return errors ourselves

	fs.StringVar(&cfg.PCAPPath, "pcap", cfg.PCAPPath, "absolute path to input PCAP file")
	fs.StringVar(&cfg.Interface, "interface", cfg.Interface, "network interface for live capture")
	fs.StringVar(&cfg.BPF, "bpf", cfg.BPF, "BPF filter for packet capture (empty = capture all)")
	fs.StringVar(&cfg.OutputDirectory, "output", cfg.OutputDirectory, "output directory (created automatically if missing)")
	fs.StringVar(&cfg.OUIPath, "oui", cfg.OUIPath, "path to IEEE OUI or Wireshark manuf file for MAC vendor lookup")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, error")
	fs.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "log format: text or json")
	fs.StringVar(&cfg.LogOutput, "log-output", cfg.LogOutput, "log output: stdout, stderr, or a file path (default: ./output/discovery.log)")
	fs.DurationVar(&cfg.OfflineAfter, "offline-after", cfg.OfflineAfter, "asset offline threshold duration")
	fs.IntVar(&cfg.QueueSize, "queue-size", cfg.QueueSize, "packet queue size")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "packet processing workers")
	fs.DurationVar(&cfg.FlushEvery, "flush-every", cfg.FlushEvery, "database flush interval")
	fs.IntVar(&cfg.BatchSize, "batch-size", cfg.BatchSize, "database batch size")

	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database file path (default: ./output/discovery.db)")
	fs.BoolVar(&cfg.DBWAL, "db-wal", cfg.DBWAL, "enable SQLite WAL journal mode (default true)")
	fs.DurationVar(&cfg.DBBusyTimeout, "db-busy-timeout", cfg.DBBusyTimeout, "SQLite busy_timeout pragma (default 5s)")
	fs.BoolVar(&cfg.KeepJSONOutput, "keep-json-output", cfg.KeepJSONOutput, "keep writing JSON output files even when --db is set")

	fs.IntVar(&cfg.LoadLimit, "load-limit", cfg.LoadLimit, "max assets loaded from DB at startup; 0 = unlimited (default 1000)")
	fs.DurationVar(&cfg.LoadWindow, "load-window", cfg.LoadWindow, "load only assets seen within this window (default 24h)")
	fs.DurationVar(&cfg.EvictAfter, "evict-after", cfg.EvictAfter, "evict offline assets after this duration; 0 = 7×load-window")

	fs.StringVar(&cfg.APIAddr, "api-addr", cfg.APIAddr, "bind address for API/UI HTTP server (empty = disabled; e.g. 127.0.0.1:8080)")
	fs.BoolVar(&cfg.UIEnabled, "ui", cfg.UIEnabled, "serve embedded dashboard at the root path")
	fs.DurationVar(&cfg.UIRefreshEvery, "ui-refresh-every", cfg.UIRefreshEvery, "dashboard polling interval (1s–5m, default 5s)")
	fs.DurationVar(&cfg.APIReadTimeout, "api-read-timeout", cfg.APIReadTimeout, "server read timeout (default 5s)")

	if err := fs.Parse(args); err != nil {
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
	c.OUIPath = strings.TrimSpace(c.OUIPath)

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
			if err := os.MkdirAll(c.OutputDirectory, 0o755); err != nil {
				return fmt.Errorf("create --output directory %q: %w", c.OutputDirectory, err)
			}
		} else {
			return fmt.Errorf("--output directory %q: %w", c.OutputDirectory, err)
		}
	} else if !info.IsDir() {
		return fmt.Errorf("--output %q is not a directory", c.OutputDirectory)
	}

	// Persistence validation (only when --db is set).
	if c.DBPath != "" {
		c.DBPath = strings.TrimSpace(c.DBPath)
		if info, err := os.Stat(c.DBPath); err == nil {
			if info.IsDir() {
				return fmt.Errorf("--db %q is a directory, expected a file path", c.DBPath)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("--db %q: %w", c.DBPath, err)
		}
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return fmt.Errorf("invalid --log-format %q: must be text or json", c.LogFormat)
	}
	if c.KeepJSONOutput && c.DBPath == "" {
		return errors.New("--keep-json-output is only meaningful when --db is set")
	}
	if c.OUIPath != "" {
		if info, err := os.Stat(c.OUIPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("--oui file %q does not exist", c.OUIPath)
			}
			return fmt.Errorf("--oui file %q: %w", c.OUIPath, err)
		} else if info.IsDir() {
			return fmt.Errorf("--oui %q is a directory, expected a file", c.OUIPath)
		}
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
	if c.LoadWindow <= 0 {
		return errors.New("--load-window must be greater than zero")
	}
	if c.LoadLimit < 0 {
		return errors.New("--load-limit must be >= 0")
	}
	if c.EvictAfter < 0 {
		return errors.New("--evict-after must be >= 0")
	}
	if c.UIEnabled && c.APIAddr == "" {
		return errors.New("--ui requires --api-addr to be set")
	}
	if c.UIRefreshEvery < 0 {
		return errors.New("--ui-refresh-every must be >= 0")
	}
	if c.APIReadTimeout < 0 {
		return errors.New("--api-read-timeout must be >= 0")
	}
	// Clamp UI refresh to sensible bounds
	if c.UIRefreshEvery > 0 && c.UIRefreshEvery < time.Second {
		c.UIRefreshEvery = time.Second
	}
	if c.UIRefreshEvery > 5*time.Minute {
		c.UIRefreshEvery = 5 * time.Minute
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
  --oui         Optional IEEE OUI or Wireshark manuf file for MAC vendor lookup.
 
Capture options:
  --bpf         BPF filter expression. Default: empty (capture all packets).
 
Processing options:
  --offline-after   Asset offline threshold duration. Default: 5m.
  --queue-size      Packet queue size. Default: 4096.
  --workers         Packet processing workers. Default: 1.
  --flush-every     Flush interval for writing results. Default: 5s.
  --batch-size      Batch size for writing results. Default: 500.
 
Logging:
  --log-level   	Log level: debug, info, warn, error. Default: info.
  --log-format  	Log format: text or json. Default: text.
  --log-output  	Log output: stdout, stderr, or a file path. Default: stdout.

Persistence:
  --db                 	SQLite database path (enables persistent storage).
  --db-wal             	Enable SQLite WAL. Default: true.
  --db-busy-timeout    	SQLite busy_timeout. Default: 5s.
  --keep-json-output   	Write JSON files in --output even when --db is set.
  --load-limit         	Max assets to load from DB at startup. Default: 1000.
  --load-window        	Load only assets last seen within this window. Default: 24h.
  --evict-after        	Evict offline assets after this duration. Default: 0 (= 7×load-window).

API / Dashboard:
  --api-addr           	Bind address for HTTP server (empty = disabled, e.g. 127.0.0.1:8080).
  --ui                 	Serve embedded dashboard at root path (requires --api-addr).
  --ui-refresh-every   	Dashboard polling interval. Default: 5s.
  --api-read-timeout   	Server read timeout. Default: 5s.

Environment variable:
  DISCOVERY_PCAP, DISCOVERY_INTERFACE, DISCOVERY_OUTPUT,
  DISCOVERY_OUI, DISCOVERY_BPF, DISCOVERY_OFFLINE_AFTER,
  DISCOVERY_LOG_LEVEL, DISCOVERY_LOG_FORMAT, DISCOVERY_LOG_OUTPUT,
  DISCOVERY_QUEUE_SIZE, DISCOVERY_WORKERS,
  DISCOVERY_FLUSH_EVERY, DISCOVERY_BATCH_SIZE,
  DISCOVERY_DB, DISCOVERY_DB_WAL, DISCOVERY_DB_BUSY_TIMEOUT,
  DISCOVERY_KEEP_JSON_OUTPUT,
  DISCOVERY_LOAD_LIMIT, DISCOVERY_LOAD_WINDOW, DISCOVERY_EVICT_AFTER,
  DISCOVERY_API_ADDR, DISCOVERY_UI, DISCOVERY_UI_REFRESH_EVERY,
  DISCOVERY_API_READ_TIMEOUT
`
}

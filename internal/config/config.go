// config.go currently parses the minimal CLI config used by the prototype.
//
// Long-term responsibilities for this file/package:
//   - define the canonical Config struct used by cmd/discovery and pipeline;
//   - combine flags, environment defaults, and validation;
//   - support PCAP/live modes, BPF, database path, API address, lifecycle
//     thresholds, persistence intervals, analyzer mode, and output format.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

const (
	DefaultLogLevel = "info"
	DefaultBPF      = "arp or (udp and (port 67 or port 68))"
)

var ErrHelp = flag.ErrHelp

type Config struct {
	PCAPPath string
	LogLevel string
	BPF      string
}

func Parse(args []string) (*Config, error) {
	cfg := &Config{
		LogLevel: DefaultLogLevel,
		BPF:      DefaultBPF, // Berkeley Packet Filter
	}

	fs := flag.NewFlagSet("discovery", flag.ContinueOnError) // Return a descriptive error
	fs.SetOutput(io.Discard)                                 // ignore default error output
	fs.StringVar(&cfg.PCAPPath, "pcap", cfg.PCAPPath, "absolute path to input PCAP file")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, error")
	fs.StringVar(&cfg.BPF, "bpf", cfg.BPF, "BPF filter for packet capture")

	if err := fs.Parse(args); err != nil {
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

	if c.PCAPPath == "" {
		return errors.New("--pcap is required")
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid --log-level %q", c.LogLevel)
	}

	return nil
}

func Usage() string {
	return `Usage:
  discovery --pcap <file> [--log-level <level>] [--bpf <filter>]

Flags:
  --pcap        Path to input PCAP file. Required.
  --log-level   Log level: debug, info, warn, error. Default: info.
  --bpf         BPF filter. Default: arp or (udp and (port 67 or port 68)).
`
}

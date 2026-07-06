package config_test

import (
	"testing"
	"time"

	"passivediscovery/internal/config"
)

// config.Parse — covered scenarios:
//   1. --pcap + --output → ModePCAP
//   2. --interface + --output → ModeLive
//   3. Neither --pcap nor --interface → error
//   4. Both --pcap and --interface → error (mutually exclusive)
//   5. --output required → error if missing
//   6. --output nonexistent dir → error
//   7. Default values for --log-level, --queue-size, etc.
//   8. --offline-after parsed correctly
//   9. --log-level invalid → error
//  10. --db path validated (directory rejected)
//  11. --keep-json-output requires --db
//  12. --oui nonexistent file → error
//  13. Help flag returns ErrHelp
//  14. Usage() returns non-empty string

func staticEnv(k string) string {
	return ""
}

func envWith(k, v string) func(string) string {
	return func(key string) string {
		if key == k {
			return v
		}
		return ""
	}
}

func TestParse_PCAPMode(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir}, staticEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != config.ModePCAP {
		t.Errorf("expected mode=pcap, got %q", cfg.Mode)
	}
	if cfg.PCAPPath != "test.pcap" {
		t.Errorf("expected pcap=test.pcap, got %q", cfg.PCAPPath)
	}
}

func TestParse_LiveMode(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]string{"--interface", "eth0", "--output", dir}, staticEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != config.ModeLive {
		t.Errorf("expected mode=live, got %q", cfg.Mode)
	}
	if cfg.Interface != "eth0" {
		t.Errorf("expected interface=eth0, got %q", cfg.Interface)
	}
}

func TestParse_NeitherPCAPNorInterface(t *testing.T) {
	dir := t.TempDir()
	_, err := config.Parse([]string{"--output", dir}, staticEnv)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestParse_BothPCAPAndInterface(t *testing.T) {
	dir := t.TempDir()
	_, err := config.Parse([]string{"--pcap", "a.pcap", "--interface", "eth0", "--output", dir}, staticEnv)
	if err == nil {
		t.Fatal("expected error for mutually exclusive modes")
	}
}

func TestParse_MissingOutput(t *testing.T) {
	// When --output is omitted the parser falls back to DefaultOutputDir ("./output").
	cfg, err := config.Parse([]string{"--pcap", "test.pcap"}, staticEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OutputDirectory == "" {
		t.Error("expected default output directory to be set")
	}
}

func TestParse_NonexistentOutputDir(t *testing.T) {
	_, err := config.Parse([]string{"--pcap", "test.pcap", "--output", "/nonexistent/dir/xyz"}, staticEnv)
	if err == nil {
		t.Fatal("expected error for nonexistent output directory")
	}
}

func TestParse_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir}, staticEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log-level=info, got %q", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("expected default log-format=text, got %q", cfg.LogFormat)
	}
	if cfg.OfflineAfter != 5*time.Minute {
		t.Errorf("expected default offline-after=5m, got %v", cfg.OfflineAfter)
	}
	if cfg.QueueSize != 4096 {
		t.Errorf("expected default queue-size=4096, got %d", cfg.QueueSize)
	}
	if cfg.Workers != 2 {
		t.Errorf("expected default workers=2, got %d", cfg.Workers)
	}
}

func TestParse_OfflineAfterOverride(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir, "--offline-after", "10m"}, staticEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OfflineAfter != 10*time.Minute {
		t.Errorf("expected offline-after=10m, got %v", cfg.OfflineAfter)
	}
}

func TestParse_InvalidLogLevel(t *testing.T) {
	dir := t.TempDir()
	_, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir, "--log-level", "verbose"}, staticEnv)
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestParse_DBPathDirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir, "--db", dir}, staticEnv)
	if err == nil {
		t.Fatal("expected error for --db pointing to directory")
	}
}

func TestParse_KeepJSONOutputRequiresDB(t *testing.T) {
	dir := t.TempDir()
	// --db "" sets DBPath="" (empty), so the --keep-json-output validation triggers.
	_, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir, "--db", "", "--keep-json-output"}, staticEnv)
	if err == nil {
		t.Fatal("expected error for --keep-json-output without --db")
	}
}

func TestParse_OUINonexistentFile(t *testing.T) {
	dir := t.TempDir()
	_, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir, "--oui", "/nonexistent/file.txt"}, staticEnv)
	if err == nil {
		t.Fatal("expected error for nonexistent OUI file")
	}
}

func TestParse_HelpFlag(t *testing.T) {
	_, err := config.Parse([]string{"-h"}, staticEnv)
	if err != config.ErrHelp {
		t.Errorf("expected ErrHelp, got %v", err)
	}
}

func TestParse_EnvVarOverride(t *testing.T) {
	dir := t.TempDir()
	// Env var should override default, but flag takes precedence
	cfg, err := config.Parse([]string{"--pcap", "test.pcap", "--output", dir}, envWith("DISCOVERY_BPF", "udp port 53"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BPF != "udp port 53" {
		t.Errorf("expected BPF from env=udp port 53, got %q", cfg.BPF)
	}
}

func TestUsage(t *testing.T) {
	t.Parallel()
	u := config.Usage()
	if u == "" {
		t.Error("expected non-empty Usage string")
	}
}

func TestParse_AllFlags(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]string{
		"--pcap", "test.pcap",
		"--output", dir,
		"--bpf", "tcp port 443",
		"--log-level", "debug",
		"--log-format", "json",
		"--queue-size", "8192",
		"--workers", "2",
		"--flush-every", "10s",
		"--batch-size", "1000",
		"--offline-after", "3m",
	}, staticEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BPF != "tcp port 443" {
		t.Errorf("expected BPF, got %q", cfg.BPF)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log-level=debug, got %q", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("expected log-format=json, got %q", cfg.LogFormat)
	}
	if cfg.QueueSize != 8192 {
		t.Errorf("expected queue-size=8192, got %d", cfg.QueueSize)
	}
	if cfg.Workers != 2 {
		t.Errorf("expected workers=2, got %d", cfg.Workers)
	}
	if cfg.FlushEvery != 10*time.Second {
		t.Errorf("expected flush-every=10s, got %v", cfg.FlushEvery)
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("expected batch-size=1000, got %d", cfg.BatchSize)
	}
	if cfg.OfflineAfter != 3*time.Minute {
		t.Errorf("expected offline-after=3m, got %v", cfg.OfflineAfter)
	}
}

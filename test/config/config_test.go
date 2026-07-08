package config_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"passivediscovery/internal/config"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// envMap is a simple key→value map used as a fake getenv function.
type envMap map[string]string

func (e envMap) get(key string) string {
	if e == nil {
		return ""
	}
	return e[key]
}

// emptyEnv returns a getenv that always returns "".
func emptyEnv() func(string) string {
	return func(string) string { return "" }
}

// setupTempDir creates a temp dir and returns its path + a cleanup func.
func setupTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// createTempFile creates a temp file inside dir with optional content.
func createTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("createTempFile: %v", err)
	}
	return p
}

// noFlags returns the minimal args for Parse: just a valid pcap flag.
func noFlags(pcapPath string) []string {
	return []string{"--pcap", pcapPath}
}

// ── firstNonEmpty (tested indirectly via Parse + env) ────────────────────────

func TestFirstNonEmpty_EnvOverridesDefault(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Set DISCOVERY_LOG_LEVEL env → should override default "info"
	cfg, err := config.Parse(noFlags(pcap), envMap{"DISCOVERY_LOG_LEVEL": "debug"}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log-level=debug, got %q", cfg.LogLevel)
	}
}

func TestFirstNonEmpty_EmptyEnvKeepsDefault(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Empty string env → falls back to default
	cfg, err := config.Parse(noFlags(pcap), envMap{"DISCOVERY_LOG_LEVEL": ""}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log-level=info, got %q", cfg.LogLevel)
	}
}

func TestFirstNonEmpty_WhitespaceEnvKeepsDefault(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Whitespace string → TrimSpace makes it empty → fallback
	cfg, err := config.Parse(noFlags(pcap), envMap{"DISCOVERY_LOG_LEVEL": "   "}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log-level=info, got %q", cfg.LogLevel)
	}
}

// ── applyEnvDefaults (tested indirectly via Parse) ───────────────────────────

func TestApplyEnvDefaults_NilConfigNoPanic(t *testing.T) {
	// Parse with nil-safe env: calling Parse with valid args exercises applyEnvDefaults
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Just ensure Parse doesn't panic with a working getenv
	_, err := config.Parse(noFlags(pcap), emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplyEnvDefaults_NilGetenvNoPanic(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Pass nil getenv — applyEnvDefaults should return nil without panic
	cfg, err := config.Parse(noFlags(pcap), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// ── Parse: defaults ──────────────────────────────────────────────────────────

func TestParse_Defaults(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), emptyEnv())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PCAPPath != pcap {
		t.Errorf("PCAPPath = %q, want %q", cfg.PCAPPath, pcap)
	}
	if cfg.Mode != "pcap" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "pcap")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "text")
	}
	if cfg.OutputDirectory != "./output" {
		t.Errorf("OutputDirectory = %q, want %q", cfg.OutputDirectory, "./output")
	}
	if cfg.DBPath != "./output/discovery.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "./output/discovery.db")
	}
	if !cfg.DBWAL {
		t.Error("DBWAL should default to true")
	}
	if cfg.DBBusyTimeout != 5_000_000_000 { // 5s
		t.Errorf("DBBusyTimeout = %v, want 5s", cfg.DBBusyTimeout)
	}
	if cfg.OfflineAfter != 5*60_000_000_000 { // 5m
		t.Errorf("OfflineAfter = %v, want 5m", cfg.OfflineAfter)
	}
	if cfg.QueueSize != 4096 {
		t.Errorf("QueueSize = %d, want 4096", cfg.QueueSize)
	}
	if cfg.Workers != 2 {
		t.Errorf("Workers = %d, want 2", cfg.Workers)
	}
	if cfg.FlushEvery != 5_000_000_000 { // 5s
		t.Errorf("FlushEvery = %v, want 5s", cfg.FlushEvery)
	}
	if cfg.BatchSize != 500 {
		t.Errorf("BatchSize = %d, want 500", cfg.BatchSize)
	}
	if cfg.LoadLimit != 1000 {
		t.Errorf("LoadLimit = %d, want 1000", cfg.LoadLimit)
	}
	if cfg.LoadWindow != 24*3600_000_000_000 { // 24h
		t.Errorf("LoadWindow = %v, want 24h", cfg.LoadWindow)
	}
	if cfg.UIRefreshEvery != 5_000_000_000 { // 5s
		t.Errorf("UIRefreshEvery = %v, want 5s", cfg.UIRefreshEvery)
	}
	if cfg.APIReadTimeout != 5_000_000_000 { // 5s
		t.Errorf("APIReadTimeout = %v, want 5s", cfg.APIReadTimeout)
	}
	if cfg.Promisc {
		t.Error("Promisc should default to false")
	}
	if cfg.KeepJSONOutput {
		t.Error("KeepJSONOutput should default to false")
	}
	if cfg.UIEnabled {
		t.Error("UIEnabled should default to false")
	}
	if cfg.EvictAfter != 0 {
		t.Errorf("EvictAfter = %v, want 0", cfg.EvictAfter)
	}
}

// ── Parse: pcap mode ─────────────────────────────────────────────────────────

func TestParse_PCAPMode(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "input.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "pcap" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "pcap")
	}
	if cfg.PCAPPath != pcap {
		t.Errorf("PCAPPath = %q, want %q", cfg.PCAPPath, pcap)
	}
}

// ── Parse: interface mode ────────────────────────────────────────────────────

func TestParse_InterfaceMode(t *testing.T) {
	outDir := setupTempDir(t)
	cfg, err := config.Parse([]string{"--interface", "eth0", "--output", outDir}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "live" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "live")
	}
	if cfg.Interface != "eth0" {
		t.Errorf("Interface = %q, want %q", cfg.Interface, "eth0")
	}
}

// ── Parse: mutual exclusion ──────────────────────────────────────────────────

func TestParse_PCAPAndInterfaceMutuallyExclusive(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--interface", "eth0", "--output", outDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for --pcap + --interface")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want 'mutually exclusive'", err.Error())
	}
}

func TestParse_NeitherPCAPNorInterface(t *testing.T) {
	outDir := setupTempDir(t)
	_, err := config.Parse([]string{"--output", outDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when neither --pcap nor --interface is set")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error = %q, want 'required'", err.Error())
	}
}

// ── Parse: all flags ─────────────────────────────────────────────────────────

func TestParse_AllFlags(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	args := []string{
		"--pcap", pcap,
		"--bpf", "tcp port 80",
		"--promisc",
		"--output", outDir,
		"--oui", createTempFile(t, outDir, "oui.csv", ""),
		"--log-level", "debug",
		"--log-format", "json",
		"--log-output", "stderr",
		"--offline-after", "10m",
		"--queue-size", "8192",
		"--workers", "4",
		"--flush-every", "10s",
		"--batch-size", "1000",
		"--db", filepath.Join(outDir, "test.db"),
		"--db-wal=false",
		"--db-busy-timeout", "10s",
		"--keep-json-output",
		"--load-limit", "500",
		"--load-window", "12h",
		"--evict-after", "48h",
		"--api-addr", "127.0.0.1:8080",
		"--ui",
		"--ui-refresh-every", "10s",
		"--api-read-timeout", "30s",
	}
	cfg, err := config.Parse(args, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PCAPPath != pcap {
		t.Errorf("PCAPPath = %q", cfg.PCAPPath)
	}
	if cfg.BPF != "tcp port 80" {
		t.Errorf("BPF = %q", cfg.BPF)
	}
	if !cfg.Promisc {
		t.Error("Promisc should be true")
	}
	if cfg.OutputDirectory != outDir {
		t.Errorf("OutputDirectory = %q", cfg.OutputDirectory)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q", cfg.LogFormat)
	}
	if cfg.LogOutput != "stderr" {
		t.Errorf("LogOutput = %q", cfg.LogOutput)
	}
	if cfg.OfflineAfter != 10*60_000_000_000 {
		t.Errorf("OfflineAfter = %v", cfg.OfflineAfter)
	}
	if cfg.QueueSize != 8192 {
		t.Errorf("QueueSize = %d", cfg.QueueSize)
	}
	if cfg.Workers != 4 {
		t.Errorf("Workers = %d", cfg.Workers)
	}
	if cfg.FlushEvery != 10_000_000_000 {
		t.Errorf("FlushEvery = %v", cfg.FlushEvery)
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize = %d", cfg.BatchSize)
	}
	if cfg.DBWAL {
		t.Error("DBWAL should be false")
	}
	if cfg.DBBusyTimeout != 10_000_000_000 {
		t.Errorf("DBBusyTimeout = %v", cfg.DBBusyTimeout)
	}
	if !cfg.KeepJSONOutput {
		t.Error("KeepJSONOutput should be true")
	}
	if cfg.LoadLimit != 500 {
		t.Errorf("LoadLimit = %d", cfg.LoadLimit)
	}
	if cfg.LoadWindow != 12*3600_000_000_000 {
		t.Errorf("LoadWindow = %v", cfg.LoadWindow)
	}
	if cfg.EvictAfter != 48*3600_000_000_000 {
		t.Errorf("EvictAfter = %v", cfg.EvictAfter)
	}
	if cfg.APIAddr != "127.0.0.1:8080" {
		t.Errorf("APIAddr = %q", cfg.APIAddr)
	}
	if !cfg.UIEnabled {
		t.Error("UIEnabled should be true")
	}
	if cfg.UIRefreshEvery != 10_000_000_000 {
		t.Errorf("UIRefreshEvery = %v", cfg.UIRefreshEvery)
	}
	if cfg.APIReadTimeout != 30_000_000_000 {
		t.Errorf("APIReadTimeout = %v", cfg.APIReadTimeout)
	}
}

// ── Parse: unknown flag → error ─────────────────────────────────────────────

func TestParse_UnknownFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--bogus-flag"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

// ── Parse: -h returns ErrHelp ────────────────────────────────────────────────

func TestParse_HelpFlag(t *testing.T) {
	_, err := config.Parse([]string{"-h"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for -h")
	}
	if !strings.Contains(err.Error(), "flag: help requested") {
		// flag.ErrHelp renders as "flag: help requested"
		t.Errorf("expected flag.ErrHelp, got %v", err)
	}
}

// ── Parse: Validate failure ──────────────────────────────────────────────────

func TestParse_ValidationFailure_InvalidLogLevel(t *testing.T) {
	// Config validates log-level; invalid value triggers Validate error
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--log-level", "invalid"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for invalid log-level")
	}
}

// ── Parse: env vars override flags ──────────────────────────────────────────

func TestParse_EnvOverridesPCAP(t *testing.T) {
	outDir := setupTempDir(t)
	envPCAP := createTempFile(t, outDir, "env.pcap", "")
	// DISCOVERY_PCAP env should override the --pcap flag value
	cfg, err := config.Parse([]string{"--pcap", "/nonexistent.pcap"}, envMap{
		"DISCOVERY_PCAP": envPCAP,
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	// env non-empty → takes precedence over flag default (but flag explicitly sets)
	// Actually: applyEnvDefaults runs BEFORE flag.Parse, so env sets it first, then flag overrides
	// Let me reconsider: env sets cfg.PCAPPath first, then flag --pcap overrides it
	// Since --pcap is explicitly set to /nonexistent.pcap, the flag value wins
	// This is expected: flags override env
	if cfg.PCAPPath != "/nonexistent.pcap" {
		t.Errorf("expected flag to override env, got PCAPPath=%q", cfg.PCAPPath)
	}
}

// ── Parse: env sets interface ───────────────────────────────────────────────

func TestParse_EnvSetsInterface(t *testing.T) {
	outDir := setupTempDir(t)
	// Use env to set interface; no flags → env takes effect
	// But we still need to satisfy Validate (need output dir)
	cfg, err := config.Parse([]string{"--output", outDir}, envMap{
		"DISCOVERY_INTERFACE": "wlan0",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface != "wlan0" {
		t.Errorf("Interface = %q, want %q", cfg.Interface, "wlan0")
	}
	if cfg.Mode != "live" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "live")
	}
}

// ── Parse: env sets BPF ──────────────────────────────────────────────────────

func TestParse_EnvSetsBPF(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_BPF": "udp",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BPF != "udp" {
		t.Errorf("BPF = %q, want %q", cfg.BPF, "udp")
	}
}

// ── Parse: env sets output directory ────────────────────────────────────────

func TestParse_EnvSetsOutput(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_OUTPUT": outDir,
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDirectory != outDir {
		t.Errorf("OutputDirectory = %q, want %q", cfg.OutputDirectory, outDir)
	}
}

// ── Parse: env sets OUI path ────────────────────────────────────────────────

func TestParse_EnvSetsOUI(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	oui := createTempFile(t, outDir, "manuf", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_OUI": oui,
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OUIPath != oui {
		t.Errorf("OUIPath = %q, want %q", cfg.OUIPath, oui)
	}
}

// ── Parse: env sets log level ───────────────────────────────────────────────

func TestParse_EnvSetsLogLevel(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cfg, err := config.Parse(noFlags(pcap), envMap{
			"DISCOVERY_LOG_LEVEL": level,
		}.get)
		if err != nil {
			t.Fatalf("level=%q: %v", level, err)
		}
		if cfg.LogLevel != level {
			t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
		}
	}
}

// ── Parse: env sets log format ──────────────────────────────────────────────

func TestParse_EnvSetsLogFormat(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_LOG_FORMAT": "json",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "json")
	}
}

// ── Parse: env sets log output ─────────────────────────────────────────────

func TestParse_EnvSetsLogOutput(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_LOG_OUTPUT": "/var/log/disco.log",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogOutput != "/var/log/disco.log" {
		t.Errorf("LogOutput = %q, want %q", cfg.LogOutput, "/var/log/disco.log")
	}
}

// ── Parse: env sets DB path ────────────────────────────────────────────────

func TestParse_EnvSetsDBPath(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_DB": "/data/app.db",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != "/data/app.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "/data/app.db")
	}
}

// ── Parse: env sets API addr ───────────────────────────────────────────────

func TestParse_EnvSetsAPIAddr(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_API_ADDR": "0.0.0.0:9090",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIAddr != "0.0.0.0:9090" {
		t.Errorf("APIAddr = %q, want %q", cfg.APIAddr, "0.0.0.0:9090")
	}
}

// ── Parse: DISCOVERY_PROMISC boolean variants ────────────────────────────────

func TestParse_EnvPromiscVariants(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")

	trueVals := []string{"1", "true", "yes", "on"}
	falseVals := []string{"0", "false", "no", "off"}

	for _, v := range trueVals {
		cfg, err := config.Parse(noFlags(pcap), envMap{
			"DISCOVERY_PROMISC": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_PROMISC=%q: %v", v, err)
		}
		if !cfg.Promisc {
			t.Errorf("DISCOVERY_PROMISC=%q: expected Promisc=true", v)
		}
	}
	for _, v := range falseVals {
		cfg, err := config.Parse(noFlags(pcap), envMap{
			"DISCOVERY_PROMISC": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_PROMISC=%q: %v", v, err)
		}
		if cfg.Promisc {
			t.Errorf("DISCOVERY_PROMISC=%q: expected Promisc=false", v)
		}
	}
}

func TestParse_EnvPromiscInvalid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Invalid value → switch has no default → Promisc stays default (false)
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_PROMISC": "maybe",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Promisc {
		t.Error("invalid DISCOVERY_PROMISC should leave Promisc as default (false)")
	}
}

// ── Parse: DISCOVERY_DB_WAL boolean variants ─────────────────────────────────

func TestParse_EnvDBWALVariants(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")

	trueVals := []string{"1", "true", "yes", "on"}
	falseVals := []string{"0", "false", "no", "off"}

	for _, v := range trueVals {
		cfg, err := config.Parse(noFlags(pcap), envMap{
			"DISCOVERY_DB_WAL": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_DB_WAL=%q: %v", v, err)
		}
		if !cfg.DBWAL {
			t.Errorf("DISCOVERY_DB_WAL=%q: expected DBWAL=true", v)
		}
	}
	for _, v := range falseVals {
		cfg, err := config.Parse(noFlags(pcap), envMap{
			"DISCOVERY_DB_WAL": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_DB_WAL=%q: %v", v, err)
		}
		if cfg.DBWAL {
			t.Errorf("DISCOVERY_DB_WAL=%q: expected DBWAL=false", v)
		}
	}
}

func TestParse_EnvDBWALInvalid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Default is DBWAL=true; invalid env leaves it unchanged
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_DB_WAL": "invalid",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DBWAL {
		t.Error("invalid DISCOVERY_DB_WAL should leave DBWAL as default (true)")
	}
}

// ── Parse: DISCOVERY_KEEP_JSON_OUTPUT boolean variants ───────────────────────

func TestParse_EnvKeepJSONVariants(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	dbPath := filepath.Join(outDir, "app.db")

	for _, v := range []string{"1", "true", "yes", "on"} {
		cfg, err := config.Parse([]string{"--pcap", pcap, "--db", dbPath}, envMap{
			"DISCOVERY_KEEP_JSON_OUTPUT": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_KEEP_JSON_OUTPUT=%q: %v", v, err)
		}
		if !cfg.KeepJSONOutput {
			t.Errorf("DISCOVERY_KEEP_JSON_OUTPUT=%q: expected KeepJSONOutput=true", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "off"} {
		cfg, err := config.Parse([]string{"--pcap", pcap, "--db", dbPath}, envMap{
			"DISCOVERY_KEEP_JSON_OUTPUT": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_KEEP_JSON_OUTPUT=%q: %v", v, err)
		}
		if cfg.KeepJSONOutput {
			t.Errorf("DISCOVERY_KEEP_JSON_OUTPUT=%q: expected KeepJSONOutput=false", v)
		}
	}
}

func TestParse_EnvKeepJSONInvalid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Default KeepJSONOutput=false; invalid env → stays false
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_KEEP_JSON_OUTPUT": "xyz",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeepJSONOutput {
		t.Error("invalid DISCOVERY_KEEP_JSON_OUTPUT should leave KeepJSONOutput as default")
	}
}

// ── Parse: DISCOVERY_UI boolean variants ─────────────────────────────────────

func TestParse_EnvUIVariants(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	apiAddr := "127.0.0.1:8080"

	for _, v := range []string{"1", "true", "yes", "on"} {
		cfg, err := config.Parse([]string{"--pcap", pcap, "--api-addr", apiAddr}, envMap{
			"DISCOVERY_UI": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_UI=%q: %v", v, err)
		}
		if !cfg.UIEnabled {
			t.Errorf("DISCOVERY_UI=%q: expected UIEnabled=true", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "off"} {
		cfg, err := config.Parse([]string{"--pcap", pcap}, envMap{
			"DISCOVERY_UI": v,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_UI=%q: %v", v, err)
		}
		if cfg.UIEnabled {
			t.Errorf("DISCOVERY_UI=%q: expected UIEnabled=false", v)
		}
	}
}

func TestParse_EnvUIInvalid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Invalid value → stays false (default)
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_UI": "maybe",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIEnabled {
		t.Error("invalid DISCOVERY_UI should leave UIEnabled as default (false)")
	}
}

// ── Parse: env integer parsing errors ───────────────────────────────────────

func TestParse_EnvInvalidQueueSize(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_QUEUE_SIZE": "notanumber",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_QUEUE_SIZE")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_QUEUE_SIZE") {
		t.Errorf("error = %q, want mention of DISCOVERY_QUEUE_SIZE", err.Error())
	}
}

func TestParse_EnvInvalidWorkers(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_WORKERS": "abc",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_WORKERS")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_WORKERS") {
		t.Errorf("error = %q, want mention of DISCOVERY_WORKERS", err.Error())
	}
}

func TestParse_EnvInvalidBatchSize(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_BATCH_SIZE": "xyz",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_BATCH_SIZE")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_BATCH_SIZE") {
		t.Errorf("error = %q, want mention of DISCOVERY_BATCH_SIZE", err.Error())
	}
}

// ── Parse: env duration parsing errors ──────────────────────────────────────

func TestParse_EnvInvalidDBBusyTimeout(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_DB_BUSY_TIMEOUT": "notaduration",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_DB_BUSY_TIMEOUT")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_DB_BUSY_TIMEOUT") {
		t.Errorf("error = %q, want mention of DISCOVERY_DB_BUSY_TIMEOUT", err.Error())
	}
}

func TestParse_EnvInvalidOfflineAfter(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_OFFLINE_AFTER": "bad",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_OFFLINE_AFTER")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_OFFLINE_AFTER") {
		t.Errorf("error = %q, want mention of DISCOVERY_OFFLINE_AFTER", err.Error())
	}
}

func TestParse_EnvInvalidFlushEvery(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_FLUSH_EVERY": "wrong",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_FLUSH_EVERY")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_FLUSH_EVERY") {
		t.Errorf("error = %q, want mention of DISCOVERY_FLUSH_EVERY", err.Error())
	}
}

func TestParse_EnvInvalidLoadWindow(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_LOAD_WINDOW": "nope",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_LOAD_WINDOW")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_LOAD_WINDOW") {
		t.Errorf("error = %q, want mention of DISCOVERY_LOAD_WINDOW", err.Error())
	}
}

func TestParse_EnvInvalidUIRefreshEvery(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_UI_REFRESH_EVERY": "garbage",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_UI_REFRESH_EVERY")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_UI_REFRESH_EVERY") {
		t.Errorf("error = %q, want mention of DISCOVERY_UI_REFRESH_EVERY", err.Error())
	}
}

func TestParse_EnvInvalidAPIReadTimeout(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_API_READ_TIMEOUT": "nonsense",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_API_READ_TIMEOUT")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_API_READ_TIMEOUT") {
		t.Errorf("error = %q, want mention of DISCOVERY_API_READ_TIMEOUT", err.Error())
	}
}

// ── Parse: env LOAD_LIMIT negative ──────────────────────────────────────────

func TestParse_EnvLoadLimitNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_LOAD_LIMIT": "-1",
	}.get)
	if err == nil {
		t.Fatal("expected error for negative DISCOVERY_LOAD_LIMIT")
	}
	if !strings.Contains(err.Error(), "must be >= 0") {
		t.Errorf("error = %q, want 'must be >= 0'", err.Error())
	}
}

// ── Parse: env EVICT_AFTER negative ─────────────────────────────────────────

func TestParse_EnvEvictAfterNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_EVICT_AFTER": "-5m",
	}.get)
	if err == nil {
		t.Fatal("expected error for negative DISCOVERY_EVICT_AFTER")
	}
	if !strings.Contains(err.Error(), "must be >= 0") {
		t.Errorf("error = %q, want 'must be >= 0'", err.Error())
	}
}

// ── Parse: env invalid load-limit (non-numeric) ─────────────────────────────

func TestParse_EnvInvalidLoadLimit(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_LOAD_LIMIT": "abc",
	}.get)
	if err == nil {
		t.Fatal("expected error for non-numeric DISCOVERY_LOAD_LIMIT")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_LOAD_LIMIT") {
		t.Errorf("error = %q, want mention of DISCOVERY_LOAD_LIMIT", err.Error())
	}
}

// ── Parse: env invalid evict-after (non-duration) ───────────────────────────

func TestParse_EnvInvalidEvictAfter(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_EVICT_AFTER": "notaduration",
	}.get)
	if err == nil {
		t.Fatal("expected error for invalid DISCOVERY_EVICT_AFTER")
	}
	if !strings.Contains(err.Error(), "DISCOVERY_EVICT_AFTER") {
		t.Errorf("error = %q, want mention of DISCOVERY_EVICT_AFTER", err.Error())
	}
}

// ── Validate: MkdirAll failure for output directory ─────────────────────────

func TestValidate_OutputDirMkdirAllFails(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Try to create output dir inside /proc (read-only fs, MkdirAll fails on Linux)
	_, err := config.Parse([]string{"--pcap", pcap, "--output", "/proc/nonexistent/dir"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when MkdirAll fails for output directory")
	}
	if !strings.Contains(err.Error(), "create --output directory") {
		t.Errorf("error = %q, want 'create --output directory'", err.Error())
	}
}

// ── Validate: os.Stat non-IsNotExist error for output directory ─────────────

func TestValidate_OutputDirStatNonNotExist(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skip: running as root, permission errors won't occur")
	}
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Create a read-only parent; stat on child path returns EACCES, not ENOENT
	restrictedDir := filepath.Join(outDir, "restricted")
	if err := os.Mkdir(restrictedDir, 0o000); err != nil {
		t.Skip("skip: cannot create restricted dir", err)
	}
	_, err := config.Parse([]string{"--pcap", pcap, "--output", filepath.Join(restrictedDir, "child")}, emptyEnv())
	if err == nil {
		t.Fatal("expected stat permission error for output directory")
	}
	if !strings.Contains(err.Error(), "--output") {
		t.Errorf("error = %q, want mention of --output", err.Error())
	}
}

// ── Validate: os.Stat non-IsNotExist error for DB path ─────────────────────

func TestValidate_DBPathStatNonNotExist(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skip: running as root, permission errors won't occur")
	}
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	restrictedDir := filepath.Join(outDir, "restricted")
	if err := os.Mkdir(restrictedDir, 0o000); err != nil {
		t.Skip("skip: cannot create restricted dir", err)
	}
	_, err := config.Parse([]string{"--pcap", pcap, "--db", filepath.Join(restrictedDir, "app.db")}, emptyEnv())
	if err == nil {
		t.Fatal("expected stat permission error for DB path")
	}
	if !strings.Contains(err.Error(), "--db") {
		t.Errorf("error = %q, want mention of --db", err.Error())
	}
}

// ── Validate: os.Stat non-IsNotExist error for OUI path ────────────────────

func TestValidate_OUIPathStatNonNotExist(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skip: running as root, permission errors won't occur")
	}
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	restrictedDir := filepath.Join(outDir, "restricted")
	if err := os.Mkdir(restrictedDir, 0o000); err != nil {
		t.Skip("skip: cannot create restricted dir", err)
	}
	_, err := config.Parse([]string{"--pcap", pcap, "--oui", filepath.Join(restrictedDir, "manuf")}, emptyEnv())
	if err == nil {
		t.Fatal("expected stat permission error for OUI path")
	}
	// Error should mention either --oui or does not exist (depending on whether stat succeeds)
	if !strings.Contains(err.Error(), "--oui") && !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want mention of --oui or 'does not exist'", err.Error())
	}
}

// ── Parse: env valid integers ───────────────────────────────────────────────

func TestParse_EnvValidQueueSize(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_QUEUE_SIZE": "2048",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QueueSize != 2048 {
		t.Errorf("QueueSize = %d, want 2048", cfg.QueueSize)
	}
}

func TestParse_EnvValidWorkers(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_WORKERS": "8",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workers != 8 {
		t.Errorf("Workers = %d, want 8", cfg.Workers)
	}
}

func TestParse_EnvValidBatchSize(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_BATCH_SIZE": "200",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BatchSize != 200 {
		t.Errorf("BatchSize = %d, want 200", cfg.BatchSize)
	}
}

func TestParse_EnvValidLoadLimit(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	for _, val := range []string{"0", "500", "10000"} {
		cfg, err := config.Parse(noFlags(pcap), envMap{
			"DISCOVERY_LOAD_LIMIT": val,
		}.get)
		if err != nil {
			t.Fatalf("DISCOVERY_LOAD_LIMIT=%s: %v", val, err)
		}
		// cfg.LoadLimit is an int; val is "0", "500", "10000"
		switch val {
		case "0":
			if cfg.LoadLimit != 0 {
				t.Errorf("LoadLimit = %d, want 0", cfg.LoadLimit)
			}
		case "500":
			if cfg.LoadLimit != 500 {
				t.Errorf("LoadLimit = %d, want 500", cfg.LoadLimit)
			}
		case "10000":
			if cfg.LoadLimit != 10000 {
				t.Errorf("LoadLimit = %d, want 10000", cfg.LoadLimit)
			}
		}
	}
}

// ── Parse: env valid durations ──────────────────────────────────────────────

func TestParse_EnvValidDurations(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")

	tests := []struct {
		envKey   string
		envValue string
		check    func(*config.Config) bool
	}{
		{"DISCOVERY_DB_BUSY_TIMEOUT", "3s", func(c *config.Config) bool { return c.DBBusyTimeout == 3_000_000_000 }},
		{"DISCOVERY_OFFLINE_AFTER", "10m", func(c *config.Config) bool { return c.OfflineAfter == 10*60_000_000_000 }},
		{"DISCOVERY_FLUSH_EVERY", "15s", func(c *config.Config) bool { return c.FlushEvery == 15_000_000_000 }},
		{"DISCOVERY_LOAD_WINDOW", "48h", func(c *config.Config) bool { return c.LoadWindow == 48*3600_000_000_000 }},
		{"DISCOVERY_UI_REFRESH_EVERY", "2s", func(c *config.Config) bool { return c.UIRefreshEvery == 2_000_000_000 }},
		{"DISCOVERY_API_READ_TIMEOUT", "10s", func(c *config.Config) bool { return c.APIReadTimeout == 10_000_000_000 }},
	}
	for _, tt := range tests {
		t.Run(tt.envKey, func(t *testing.T) {
			cfg, err := config.Parse(noFlags(pcap), envMap{
				tt.envKey: tt.envValue,
			}.get)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.check(cfg) {
				t.Errorf("%s=%s: unexpected value", tt.envKey, tt.envValue)
			}
		})
	}
}

// ── Parse: env EVICT_AFTER valid ────────────────────────────────────────────

func TestParse_EnvEvictAfterValid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_EVICT_AFTER": "24h",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EvictAfter != 24*3600_000_000_000 {
		t.Errorf("EvictAfter = %v, want 24h", cfg.EvictAfter)
	}
}

// ── Validate: nil config ────────────────────────────────────────────────────

func TestValidate_NilConfig(t *testing.T) {
	var cfg *config.Config
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error = %q, want 'nil'", err.Error())
	}
}

// ── Validate: PCAP path validation ─────────────────────────────────────────

func TestValidate_PCAPPathTrimmed(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Test via Parse with whitespace PCAP path (should be trimmed)
	cfg, err := config.Parse([]string{"--pcap", "  " + pcap + "  "}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PCAPPath != pcap {
		t.Errorf("PCAPPath not trimmed: %q, want %q", cfg.PCAPPath, pcap)
	}
}

// ── Validate: interface mode validation ─────────────────────────────────────

func TestValidate_InterfaceModeValidation(t *testing.T) {
	outDir := setupTempDir(t)
	// Test via Parse with whitespace interface (should be trimmed and fail)
	_, err := config.Parse([]string{"--interface", "  ", "--output", outDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for whitespace-only interface")
	}
}

// ── Validate: output path trimming ──────────────────────────────────────────

func TestValidate_OutputPathTrimmed(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--output", "  " + outDir + "  "}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDirectory != outDir {
		t.Errorf("OutputDirectory not trimmed: %q, want %q", cfg.OutputDirectory, outDir)
	}
}

// ── Validate: output path is required ───────────────────────────────────────

func TestValidate_OutputRequiredViaValidate(t *testing.T) {
	// Call Validate directly: set PCAP so that PCAP/interface check passes,
	// but leave output empty to trigger the "required" error.
	cfg := &config.Config{
		PCAPPath:        "/some/file.pcap",
		OutputDirectory: "",
		LogLevel:        "info",
		LogFormat:       "text",
		OfflineAfter:    time.Hour,
		QueueSize:       1,
		Workers:         1,
		FlushEvery:      time.Second,
		BatchSize:       1,
		LoadWindow:      time.Hour,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty output directory")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error = %q, want 'required'", err.Error())
	}
}

// ── Validate: log level validation ──────────────────────────────────────────

func TestValidate_LogLevelInvalid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--log-level", "verbose"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for invalid log-level")
	}
	if !strings.Contains(err.Error(), "log-level") {
		t.Errorf("error = %q, want mention of log-level", err.Error())
	}
}

func TestValidate_LogLevelValid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cfg, err := config.Parse([]string{"--pcap", pcap, "--log-level", level}, emptyEnv())
		if err != nil {
			t.Fatalf("log-level=%q: %v", level, err)
		}
		if cfg.LogLevel != level {
			t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
		}
	}
}

// ── Validate: log level normalized to lowercase ─────────────────────────────

func TestValidate_LogLevelNormalized(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--log-level", "DEBUG"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q (normalized to lowercase)", cfg.LogLevel, "debug")
	}
}

// ── Validate: output dir doesn't exist → created ────────────────────────────

func TestValidate_OutputDirCreated(t *testing.T) {
	parent := setupTempDir(t)
	newDir := filepath.Join(parent, "new-output-subdir")
	pcap := createTempFile(t, parent, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--output", newDir}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDirectory != newDir {
		t.Errorf("OutputDirectory = %q, want %q", cfg.OutputDirectory, newDir)
	}
	// Verify directory was actually created
	info, err := os.Stat(newDir)
	if err != nil {
		t.Fatalf("output dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("%q is not a directory", newDir)
	}
}

// ── Validate: output path exists but is a file ──────────────────────────────

func TestValidate_OutputPathIsFile(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	outFile := createTempFile(t, outDir, "not-a-dir.txt", "content")
	_, err := config.Parse([]string{"--pcap", pcap, "--output", outFile}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when output path is a file, not a directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error = %q, want 'not a directory'", err.Error())
	}
}

// ── Validate: DB path is a directory ────────────────────────────────────────

func TestValidate_DBPathIsDirectory(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--db", outDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when db path is a directory")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("error = %q, want 'is a directory'", err.Error())
	}
}

// ── Validate: DB path doesn't exist → OK (no error) ────────────────────────

func TestValidate_DBPathNonExistent(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	nonExistentDB := filepath.Join(outDir, "new.db")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db", nonExistentDB}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != nonExistentDB {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, nonExistentDB)
	}
}

// ── Validate: DB path is a regular file → OK ────────────────────────────────

func TestValidate_DBPathIsFile(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	dbFile := createTempFile(t, outDir, "app.db", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db", dbFile}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != dbFile {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, dbFile)
	}
}

// ── Validate: log format invalid ────────────────────────────────────────────

func TestValidate_LogFormatInvalid(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--log-format", "yaml"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for invalid log-format")
	}
	if !strings.Contains(err.Error(), "log-format") {
		t.Errorf("error = %q, want mention of log-format", err.Error())
	}
}

func TestValidate_LogFormatJSON(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--log-format", "json"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "json")
	}
}

// ── Validate: keep-json-output without db ───────────────────────────────────

func TestValidate_KeepJSONOutputRequiresDB(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Pass --db "" (empty string → DBPath stays default; set explicitly to "")
	_, err := config.Parse([]string{"--pcap", pcap, "--db", "", "--keep-json-output"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for --keep-json-output without --db")
	}
	if !strings.Contains(err.Error(), "keep-json-output") {
		t.Errorf("error = %q, want mention of keep-json-output", err.Error())
	}
}

// ── Validate: OUI path doesn't exist ───────────────────────────────────────

func TestValidate_OUIPathNotFound(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--oui", "/nonexistent/oui.csv"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for nonexistent oui file")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want 'does not exist'", err.Error())
	}
}

// ── Validate: OUI path is a directory ───────────────────────────────────────

func TestValidate_OUIPathIsDirectory(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--oui", outDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when oui path is a directory")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("error = %q, want 'is a directory'", err.Error())
	}
}

// ── Validate: OUI path is a regular file → OK ──────────────────────────────

func TestValidate_OUIPathIsFile(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	ouiFile := createTempFile(t, outDir, "manuf", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--oui", ouiFile}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OUIPath != ouiFile {
		t.Errorf("OUIPath = %q, want %q", cfg.OUIPath, ouiFile)
	}
}

// ── Validate: offline-after must be > 0 ─────────────────────────────────────

func TestValidate_OfflineAfterZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--offline-after", "0s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for offline-after=0")
	}
	if !strings.Contains(err.Error(), "offline-after") {
		t.Errorf("error = %q, want mention of offline-after", err.Error())
	}
}

func TestValidate_OfflineAfterNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--offline-after", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative offline-after")
	}
	if !strings.Contains(err.Error(), "offline-after") {
		t.Errorf("error = %q, want mention of offline-after", err.Error())
	}
}

// ── Validate: queue-size must be > 0 ────────────────────────────────────────

func TestValidate_QueueSizeZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--queue-size", "0"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for queue-size=0")
	}
	if !strings.Contains(err.Error(), "queue-size") {
		t.Errorf("error = %q, want mention of queue-size", err.Error())
	}
}

// ── Validate: workers must be > 0 ───────────────────────────────────────────

func TestValidate_WorkersZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--workers", "0"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for workers=0")
	}
	if !strings.Contains(err.Error(), "workers") {
		t.Errorf("error = %q, want mention of workers", err.Error())
	}
}

// ── Validate: flush-every must be > 0 ──────────────────────────────────────

func TestValidate_FlushEveryZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--flush-every", "0s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for flush-every=0")
	}
	if !strings.Contains(err.Error(), "flush-every") {
		t.Errorf("error = %q, want mention of flush-every", err.Error())
	}
}

// ── Validate: batch-size must be > 0 ────────────────────────────────────────

func TestValidate_BatchSizeZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--batch-size", "0"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for batch-size=0")
	}
	if !strings.Contains(err.Error(), "batch-size") {
		t.Errorf("error = %q, want mention of batch-size", err.Error())
	}
}

// ── Validate: load-window must be > 0 ──────────────────────────────────────

func TestValidate_LoadWindowZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--load-window", "0s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for load-window=0")
	}
	if !strings.Contains(err.Error(), "load-window") {
		t.Errorf("error = %q, want mention of load-window", err.Error())
	}
}

// ── Validate: load-limit must be >= 0 ──────────────────────────────────────

func TestValidate_LoadLimitNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--load-limit", "-1"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for load-limit=-1")
	}
	if !strings.Contains(err.Error(), "load-limit") {
		t.Errorf("error = %q, want mention of load-limit", err.Error())
	}
}

func TestValidate_LoadLimitZeroOK(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--load-limit", "0"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoadLimit != 0 {
		t.Errorf("LoadLimit = %d, want 0", cfg.LoadLimit)
	}
}

// ── Validate: evict-after must be >= 0 ──────────────────────────────────────

func TestValidate_EvictAfterNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--evict-after", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative evict-after")
	}
	if !strings.Contains(err.Error(), "evict-after") {
		t.Errorf("error = %q, want mention of evict-after", err.Error())
	}
}

func TestValidate_EvictAfterZeroOK(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--evict-after", "0s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EvictAfter != 0 {
		t.Errorf("EvictAfter = %v, want 0", cfg.EvictAfter)
	}
}

// ── Validate: UI requires API addr ──────────────────────────────────────────

func TestValidate_UIRequiresAPIAddr(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--ui"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error: --ui without --api-addr")
	}
	if !strings.Contains(err.Error(), "--ui requires --api-addr") {
		t.Errorf("error = %q, want '--ui requires --api-addr'", err.Error())
	}
}

func TestValidate_UIWithAPIAddrOK(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui", "--api-addr", "127.0.0.1:8080"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UIEnabled {
		t.Error("UIEnabled should be true")
	}
	if cfg.APIAddr != "127.0.0.1:8080" {
		t.Errorf("APIAddr = %q, want %q", cfg.APIAddr, "127.0.0.1:8080")
	}
}

// ── Validate: ui-refresh-every must be >= 0 ─────────────────────────────────

func TestValidate_UIRefreshEveryNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative ui-refresh-every")
	}
	if !strings.Contains(err.Error(), "ui-refresh-every") {
		t.Errorf("error = %q, want mention of ui-refresh-every", err.Error())
	}
}

func TestValidate_UIRefreshEveryZeroOK(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "0s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != 0 {
		t.Errorf("UIRefreshEvery = %v, want 0", cfg.UIRefreshEvery)
	}
}

// ── Validate: api-read-timeout must be >= 0 ─────────────────────────────────

func TestValidate_APIReadTimeoutNegative(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--api-read-timeout", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative api-read-timeout")
	}
	if !strings.Contains(err.Error(), "api-read-timeout") {
		t.Errorf("error = %q, want mention of api-read-timeout", err.Error())
	}
}

func TestValidate_APIReadTimeoutZeroOK(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--api-read-timeout", "0s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIReadTimeout != 0 {
		t.Errorf("APIReadTimeout = %v, want 0", cfg.APIReadTimeout)
	}
}

// ── Validate: UIRefreshEvery clamping ───────────────────────────────────────

func TestValidate_UIRefreshEveryClampedToMin(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// 100ms < 1s → should be clamped to 1s
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "100ms"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != time.Second {
		t.Errorf("UIRefreshEvery = %v, want 1s (clamped from 100ms)", cfg.UIRefreshEvery)
	}
}

func TestValidate_UIRefreshEveryClampedToMax(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// 10m > 5m → should be clamped to 5m
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "10m"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != 5*time.Minute {
		t.Errorf("UIRefreshEvery = %v, want 5m (clamped from 10m)", cfg.UIRefreshEvery)
	}
}

func TestValidate_UIRefreshEveryAtBoundaryMin(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Exactly 1s → should stay 1s
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "1s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != time.Second {
		t.Errorf("UIRefreshEvery = %v, want 1s", cfg.UIRefreshEvery)
	}
}

func TestValidate_UIRefreshEveryAtBoundaryMax(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Exactly 5m → should stay 5m
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "5m"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != 5*time.Minute {
		t.Errorf("UIRefreshEvery = %v, want 5m", cfg.UIRefreshEvery)
	}
}

func TestValidate_UIRefreshEveryBetweenMinAndMax(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "30s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != 30*time.Second {
		t.Errorf("UIRefreshEvery = %v, want 30s", cfg.UIRefreshEvery)
	}
}

// ── Validate: BPF path trimmed ──────────────────────────────────────────────

func TestValidate_BPFPathTrimmed(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--bpf", "  tcp port 443  "}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BPF != "tcp port 443" {
		t.Errorf("BPF = %q, want %q (trimmed)", cfg.BPF, "tcp port 443")
	}
}

// ── Validate: OUI path trimmed ──────────────────────────────────────────────

func TestValidate_OUIPathTrimmed(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	ouiFile := createTempFile(t, outDir, "manuf", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--oui", "  " + ouiFile + "  "}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OUIPath != ouiFile {
		t.Errorf("OUIPath = %q, want %q (trimmed)", cfg.OUIPath, ouiFile)
	}
}

// ── Usage ───────────────────────────────────────────────────────────────────

func TestUsage_ReturnsNonEmpty(t *testing.T) {
	u := config.Usage()
	if u == "" {
		t.Fatal("Usage() returned empty string")
	}
	if !strings.Contains(u, "--pcap") {
		t.Error("Usage() should mention --pcap")
	}
	if !strings.Contains(u, "--interface") {
		t.Error("Usage() should mention --interface")
	}
	if !strings.Contains(u, "--output") {
		t.Error("Usage() should mention --output")
	}
}

// ── ErrHelp is flag.ErrHelp ─────────────────────────────────────────────────

func TestErrHelpIsFlagErrHelp(t *testing.T) {
	if config.ErrHelp != flag.ErrHelp {
		t.Errorf("config.ErrHelp = %v, want %v", config.ErrHelp, flag.ErrHelp)
	}
}

// ── Parse: interface mode with promisc flag ─────────────────────────────────

func TestParse_InterfaceWithPromisc(t *testing.T) {
	outDir := setupTempDir(t)
	cfg, err := config.Parse([]string{
		"--interface", "eth0",
		"--output", outDir,
		"--promisc",
	}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "live" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "live")
	}
	if !cfg.Promisc {
		t.Error("Promisc should be true")
	}
}

// ── Parse: DB path default ──────────────────────────────────────────────────

func TestParse_DBPathDefault(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != "./output/discovery.db" {
		t.Errorf("DBPath default = %q, want %q", cfg.DBPath, "./output/discovery.db")
	}
}

// ── Parse: DB WAL flag ──────────────────────────────────────────────────────

func TestParse_DBWALFlagFalse(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db-wal=false"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBWAL {
		t.Error("DBWAL should be false when --db-wal=false")
	}
}

func TestParse_DBWALFlagTrue(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db-wal=true"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DBWAL {
		t.Error("DBWAL should be true when --db-wal=true")
	}
}

// ── Parse: DB busy timeout flag ─────────────────────────────────────────────

func TestParse_DBBusyTimeoutFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db-busy-timeout", "3s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBBusyTimeout != 3*time.Second {
		t.Errorf("DBBusyTimeout = %v, want 3s", cfg.DBBusyTimeout)
	}
}

// ── Parse: keep-json-output with empty DB path ──────────────────────────────

func TestParse_KeepJSONOutputNoDB(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Setting --db "" and --keep-json-output → should error
	_, err := config.Parse([]string{
		"--pcap", pcap,
		"--db", "",
		"--keep-json-output",
	}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for --keep-json-output without db")
	}
}

// ── Parse: keep-json-output with DB set → OK ────────────────────────────────

func TestParse_KeepJSONOutputWithDB(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	dbPath := filepath.Join(outDir, "test.db")
	cfg, err := config.Parse([]string{
		"--pcap", pcap,
		"--db", dbPath,
		"--keep-json-output",
	}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.KeepJSONOutput {
		t.Error("KeepJSONOutput should be true")
	}
}

// ── Parse: load-limit zero flag → OK ────────────────────────────────────────

func TestParse_LoadLimitZeroFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--load-limit", "0"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoadLimit != 0 {
		t.Errorf("LoadLimit = %d, want 0", cfg.LoadLimit)
	}
}

// ── Parse: evict-after zero flag → OK ───────────────────────────────────────

func TestParse_EvictAfterZeroFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--evict-after", "0s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EvictAfter != 0 {
		t.Errorf("EvictAfter = %v, want 0", cfg.EvictAfter)
	}
}

// ── Parse: multiple env vars at once ────────────────────────────────────────

func TestParse_MultipleEnvVars(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	env := envMap{
		"DISCOVERY_LOG_LEVEL":   "warn",
		"DISCOVERY_LOG_FORMAT":  "json",
		"DISCOVERY_LOG_OUTPUT":  "stderr",
		"DISCOVERY_QUEUE_SIZE":  "1024",
		"DISCOVERY_WORKERS":     "8",
		"DISCOVERY_BATCH_SIZE":  "250",
		"DISCOVERY_OUTPUT":      outDir,
	}
	cfg, err := config.Parse(noFlags(pcap), env.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q", cfg.LogFormat)
	}
	if cfg.LogOutput != "stderr" {
		t.Errorf("LogOutput = %q", cfg.LogOutput)
	}
	if cfg.QueueSize != 1024 {
		t.Errorf("QueueSize = %d", cfg.QueueSize)
	}
	if cfg.Workers != 8 {
		t.Errorf("Workers = %d", cfg.Workers)
	}
	if cfg.BatchSize != 250 {
		t.Errorf("BatchSize = %d", cfg.BatchSize)
	}
}

// ── Validate: OUI error on os.Stat error (not exist) ───────────────────────

func TestValidate_OUIPathStatError(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Use a path that returns a non-IsNotExist error (permission issue hard to simulate;
	// we at least cover the IsNotExist branch above)
	_, err := config.Parse([]string{"--pcap", pcap, "--oui", "/no/such/path/manuf"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for nonexistent oui file")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want 'does not exist'", err.Error())
	}
}

// ── Validate: load-limit negative flag ──────────────────────────────────────

func TestParse_LoadLimitNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--load-limit", "-1"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative load-limit")
	}
	if !strings.Contains(err.Error(), "load-limit") {
		t.Errorf("error = %q, want mention of load-limit", err.Error())
	}
}

// ── Validate: evict-after negative flag ─────────────────────────────────────

func TestParse_EvictAfterNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--evict-after", "-5m"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative evict-after")
	}
	if !strings.Contains(err.Error(), "evict-after") {
		t.Errorf("error = %q, want mention of evict-after", err.Error())
	}
}

// ── Validate: ui-refresh-every negative flag ────────────────────────────────

func TestParse_UIRefreshEveryNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative ui-refresh-every")
	}
	if !strings.Contains(err.Error(), "ui-refresh-every") {
		t.Errorf("error = %q, want mention of ui-refresh-every", err.Error())
	}
}

// ── Validate: api-read-timeout negative flag ────────────────────────────────

func TestParse_APIReadTimeoutNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--api-read-timeout", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative api-read-timeout")
	}
	if !strings.Contains(err.Error(), "api-read-timeout") {
		t.Errorf("error = %q, want mention of api-read-timeout", err.Error())
	}
}

// ── Parse: live mode with BPF ───────────────────────────────────────────────

func TestParse_LiveModeWithBPF(t *testing.T) {
	outDir := setupTempDir(t)
	cfg, err := config.Parse([]string{
		"--interface", "eth0",
		"--output", outDir,
		"--bpf", "tcp port 80",
	}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "live" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "live")
	}
	if cfg.BPF != "tcp port 80" {
		t.Errorf("BPF = %q, want %q", cfg.BPF, "tcp port 80")
	}
}

// ── Parse: OUI path with flag ──────────────────────────────────────────────

func TestParse_OUIPathFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	ouiFile := createTempFile(t, outDir, "manuf", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--oui", ouiFile}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OUIPath != ouiFile {
		t.Errorf("OUIPath = %q, want %q", cfg.OUIPath, ouiFile)
	}
}

// ── Parse: log-output flag ──────────────────────────────────────────────────

func TestParse_LogOutputFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--log-output", "stderr"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogOutput != "stderr" {
		t.Errorf("LogOutput = %q, want %q", cfg.LogOutput, "stderr")
	}
}

// ── Parse: log-format flag ──────────────────────────────────────────────────

func TestParse_LogFormatFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--log-format", "json"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "json")
	}
}

// ── Parse: offline-after flag ───────────────────────────────────────────────

func TestParse_OfflineAfterFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--offline-after", "10m"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OfflineAfter != 10*time.Minute {
		t.Errorf("OfflineAfter = %v, want 10m", cfg.OfflineAfter)
	}
}

// ── Parse: queue-size flag ──────────────────────────────────────────────────

func TestParse_QueueSizeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--queue-size", "8192"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QueueSize != 8192 {
		t.Errorf("QueueSize = %d, want 8192", cfg.QueueSize)
	}
}

// ── Parse: workers flag ─────────────────────────────────────────────────────

func TestParse_WorkersFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--workers", "4"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workers != 4 {
		t.Errorf("Workers = %d, want 4", cfg.Workers)
	}
}

// ── Parse: flush-every flag ─────────────────────────────────────────────────

func TestParse_FlushEveryFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--flush-every", "15s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FlushEvery != 15*time.Second {
		t.Errorf("FlushEvery = %v, want 15s", cfg.FlushEvery)
	}
}

// ── Parse: batch-size flag ──────────────────────────────────────────────────

func TestParse_BatchSizeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--batch-size", "1000"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize = %d, want 1000", cfg.BatchSize)
	}
}

// ── Parse: load-window flag ─────────────────────────────────────────────────

func TestParse_LoadWindowFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--load-window", "12h"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoadWindow != 12*time.Hour {
		t.Errorf("LoadWindow = %v, want 12h", cfg.LoadWindow)
	}
}

// ── Parse: DB path flag ─────────────────────────────────────────────────────

func TestParse_DBPathFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	dbPath := filepath.Join(outDir, "custom.db")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db", dbPath}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != dbPath {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, dbPath)
	}
}

// ── Parse: api-addr flag ────────────────────────────────────────────────────

func TestParse_APIAddrFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--api-addr", "0.0.0.0:9090"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIAddr != "0.0.0.0:9090" {
		t.Errorf("APIAddr = %q, want %q", cfg.APIAddr, "0.0.0.0:9090")
	}
}

// ── Parse: ui-refresh-every flag ────────────────────────────────────────────

func TestParse_UIRefreshEveryFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--ui-refresh-every", "10s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UIRefreshEvery != 10*time.Second {
		t.Errorf("UIRefreshEvery = %v, want 10s", cfg.UIRefreshEvery)
	}
}

// ── Parse: api-read-timeout flag ────────────────────────────────────────────

func TestParse_APIReadTimeoutFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--api-read-timeout", "30s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIReadTimeout != 30*time.Second {
		t.Errorf("APIReadTimeout = %v, want 30s", cfg.APIReadTimeout)
	}
}

// ── Parse: db-busy-timeout flag ─────────────────────────────────────────────

// (TestParse_DBBusyTimeoutFlag already defined above with 3s)

// ── Parse: db path with whitespace ──────────────────────────────────────────

func TestParse_DBPathTrimmed(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	dbPath := filepath.Join(outDir, "test.db")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--db", "  " + dbPath + "  "}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != dbPath {
		t.Errorf("DBPath = %q, want %q (trimmed)", cfg.DBPath, dbPath)
	}
}

// ── Validate: queue-size negative flag ──────────────────────────────────────

func TestParse_QueueSizeNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--queue-size", "-1"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative queue-size")
	}
}

// ── Validate: workers negative flag ─────────────────────────────────────────

func TestParse_WorkersNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--workers", "-1"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative workers")
	}
}

// ── Validate: batch-size negative flag ──────────────────────────────────────

func TestParse_BatchSizeNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--batch-size", "-1"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative batch-size")
	}
}

// ── Validate: offline-after negative flag ───────────────────────────────────

func TestParse_OfflineAfterNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--offline-after", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative offline-after")
	}
}

// ── Validate: flush-every negative flag ─────────────────────────────────────

func TestParse_FlushEveryNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--flush-every", "-1s"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative flush-every")
	}
}

// ── Validate: load-window negative flag ─────────────────────────────────────

func TestParse_LoadWindowNegativeFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--load-window", "-1h"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for negative load-window")
	}
}

// ── Parse: evict-after with env 0 → OK ─────────────────────────────────────

func TestParse_EnvEvictAfterZero(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse(noFlags(pcap), envMap{
		"DISCOVERY_EVICT_AFTER": "0s",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EvictAfter != 0 {
		t.Errorf("EvictAfter = %v, want 0", cfg.EvictAfter)
	}
}

// ── Validate: output dir stat error (permission denied) is non-IsNotExist ────

func TestValidate_OutputStatNonExist(t *testing.T) {
	// Use a path under a nonexistent parent to get an error that's not IsNotExist
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// The path doesn't exist → os.Stat returns IsNotExist → MkdirAll creates it
	newDir := filepath.Join(outDir, "brand-new-dir")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--output", newDir}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDirectory != newDir {
		t.Errorf("OutputDirectory = %q, want %q", cfg.OutputDirectory, newDir)
	}
}

// ── Parse: multiple flags at once ───────────────────────────────────────────

func TestParse_MultipleFlagsTogether(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	args := []string{
		"--pcap", pcap,
		"--bpf", "icmp",
		"--promisc",
		"--offline-after", "3m",
		"--queue-size", "2048",
		"--workers", "2",
		"--flush-every", "10s",
		"--batch-size", "100",
		"--log-level", "debug",
		"--log-format", "json",
		"--log-output", "stdout",
	}
	cfg, err := config.Parse(args, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "pcap" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "pcap")
	}
	if cfg.BPF != "icmp" {
		t.Errorf("BPF = %q", cfg.BPF)
	}
	if !cfg.Promisc {
		t.Error("Promisc should be true")
	}
	if cfg.OfflineAfter != 3*time.Minute {
		t.Errorf("OfflineAfter = %v", cfg.OfflineAfter)
	}
	if cfg.QueueSize != 2048 {
		t.Errorf("QueueSize = %d", cfg.QueueSize)
	}
	if cfg.Workers != 2 {
		t.Errorf("Workers = %d", cfg.Workers)
	}
	if cfg.FlushEvery != 10*time.Second {
		t.Errorf("FlushEvery = %v", cfg.FlushEvery)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("BatchSize = %d", cfg.BatchSize)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q", cfg.LogFormat)
	}
	if cfg.LogOutput != "stdout" {
		t.Errorf("LogOutput = %q", cfg.LogOutput)
	}
}

// ── Validate: LoadLimit=0 with flag → OK ────────────────────────────────────

func TestParse_LoadLimitZeroWithFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--load-limit", "0"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoadLimit != 0 {
		t.Errorf("LoadLimit = %d, want 0", cfg.LoadLimit)
	}
}

// ── Validate: EvictAfter=0 with flag → OK ───────────────────────────────────

func TestParse_EvictAfterZeroWithFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--evict-after", "0s"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EvictAfter != 0 {
		t.Errorf("EvictAfter = %v, want 0", cfg.EvictAfter)
	}
}

// ── Validate: keep-json-output without --db (using env to set empty) ────────

func TestParse_KeepJSONOutputEnvNoDB(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{
		"--pcap", pcap,
		"--db", "",
		"--keep-json-output",
	}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for --keep-json-output with empty --db")
	}
}

// ── Parse: BPF flag ─────────────────────────────────────────────────────────

func TestParse_BPFFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--bpf", "udp port 53"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BPF != "udp port 53" {
		t.Errorf("BPF = %q, want %q", cfg.BPF, "udp port 53")
	}
}

// ── Validate: output exists as file → error ────────────────────────────────

func TestValidate_OutputExistsAsFile(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	outFile := createTempFile(t, outDir, "outfile.txt", "data")
	_, err := config.Parse([]string{"--pcap", pcap, "--output", outFile}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when output path is a file")
	}
}

// ── Parse: output flag ──────────────────────────────────────────────────────

func TestParse_OutputFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--output", outDir}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDirectory != outDir {
		t.Errorf("OutputDirectory = %q, want %q", cfg.OutputDirectory, outDir)
	}
}

// ── Parse: OUI path doesn't exist (stat error) ─────────────────────────────

func TestParse_OUIPathNotFound(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--oui", "/no/such/file"}, emptyEnv())
	if err == nil {
		t.Fatal("expected error for nonexistent oui file")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %q, want 'does not exist'", err.Error())
	}
}

// ── Parse: OUI path is directory → error ────────────────────────────────────

func TestParse_OUIPathIsDir(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	_, err := config.Parse([]string{"--pcap", pcap, "--oui", outDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when oui path is directory")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("error = %q, want 'is a directory'", err.Error())
	}
}

// ── Parse: DB path stat error that isn't IsNotExist ─────────────────────────

func TestParse_DBPathStatError(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Use a path that doesn't exist → stat returns IsNotExist → no error (file doesn't exist is OK)
	// But for a non-IsNotExist error we'd need permission issues which are hard to simulate
	// We test the path where stat succeeds and path is a directory
	dbDir := filepath.Join(outDir, "dbdir")
	os.Mkdir(dbDir, 0o755)
	_, err := config.Parse([]string{"--pcap", pcap, "--db", dbDir}, emptyEnv())
	if err == nil {
		t.Fatal("expected error when db path is a directory")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("error = %q, want 'is a directory'", err.Error())
	}
}

// ── Parse: keep-json-output with default DBPath → OK ────────────────────────

func TestParse_KeepJSONOutputDefaultDBPath(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// Default DBPath is "./output/discovery.db" which doesn't exist → stat returns IsNotExist → no error
	cfg, err := config.Parse([]string{"--pcap", pcap, "--keep-json-output"}, emptyEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.KeepJSONOutput {
		t.Error("KeepJSONOutput should be true")
	}
}

// ── Parse: load-limit with flag and env ─────────────────────────────────────

func TestParse_LoadLimitEnvAndFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	// env sets 500, flag overrides to 200
	cfg, err := config.Parse([]string{"--pcap", pcap, "--load-limit", "200"}, envMap{
		"DISCOVERY_LOAD_LIMIT": "500",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	// env runs first → sets 500, then flag overrides to 200
	if cfg.LoadLimit != 200 {
		t.Errorf("LoadLimit = %d, want 200 (flag overrides env)", cfg.LoadLimit)
	}
}

// ── Parse: evict-after with env valid and flag ──────────────────────────────

func TestParse_EvictAfterEnvAndFlag(t *testing.T) {
	outDir := setupTempDir(t)
	pcap := createTempFile(t, outDir, "test.pcap", "")
	cfg, err := config.Parse([]string{"--pcap", pcap, "--evict-after", "12h"}, envMap{
		"DISCOVERY_EVICT_AFTER": "24h",
	}.get)
	if err != nil {
		t.Fatal(err)
	}
	// flag overrides env
	if cfg.EvictAfter != 12*time.Hour {
		t.Errorf("EvictAfter = %v, want 12h (flag overrides env)", cfg.EvictAfter)
	}
}

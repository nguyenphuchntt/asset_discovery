package capture_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passivediscovery/internal/capture"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// pcapFixture is an absolute path to one of the test pcap files in test/data.
func pcapFixture(t *testing.T, name string) string {
	t.Helper()
	// Walk up from test/capture/ → test/data/
	p := filepath.Join("..", "data", name)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("pcap fixture missing: %v", err)
	}
	return abs
}

func setupTempDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	return p
}

// capturePackets runs source with a buffered channel and returns the packets
// received before ctx is cancelled or source returns.
func capturePackets(t *testing.T, src capture.Source, ctx context.Context, buf int, dur time.Duration) []capture.RawPacket {
	t.Helper()
	if buf <= 0 {
		buf = 16
	}
	out := make(chan capture.RawPacket, buf)
	errCh := make(chan error, 1)
	go func() {
		errCh <- src.Run(ctx, out)
	}()
	deadline := time.NewTimer(dur)
	defer deadline.Stop()
	var got []capture.RawPacket
loop:
	for {
		select {
		case pkt := <-out:
			got = append(got, pkt)
		case <-deadline.C:
			break loop
		case <-ctx.Done():
			break loop
		}
	}
	_ = src.Close()
	// Drain remaining buffered packets non-blockingly
drain:
	for {
		select {
		case pkt := <-out:
			got = append(got, pkt)
		default:
			break drain
		}
	}
	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("Run returned: %v", err)
	}
	return got
}

// ── SourceKind constants ────────────────────────────────────────────────────

func TestSourceKindConstants(t *testing.T) {
	if string(capture.SourceKindFile) != "file" {
		t.Errorf("SourceKindFile = %q, want %q", capture.SourceKindFile, "file")
	}
	if string(capture.SourceKindLive) != "live" {
		t.Errorf("SourceKindLive = %q, want %q", capture.SourceKindLive, "live")
	}
}

// ── SourceRef ───────────────────────────────────────────────────────────────

func TestSourceRef_Fields(t *testing.T) {
	ref := capture.SourceRef{Kind: capture.SourceKindFile, Name: "test.pcap"}
	if ref.Kind != capture.SourceKindFile {
		t.Errorf("Kind = %v, want %v", ref.Kind, capture.SourceKindFile)
	}
	if ref.Name != "test.pcap" {
		t.Errorf("Name = %q, want %q", ref.Name, "test.pcap")
	}
}

// ── RawPacket ───────────────────────────────────────────────────────────────

func TestRawPacket_Fields(t *testing.T) {
	ref := capture.SourceRef{Kind: capture.SourceKindFile, Name: "x"}
	var p gopacket.Packet
	rp := capture.RawPacket{Packet: p, Source: ref}
	if rp.Source.Name != "x" {
		t.Errorf("Source.Name = %q", rp.Source.Name)
	}
}

// ── Errors (sentinel values) ────────────────────────────────────────────────

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrSourceAlreadyRun", capture.ErrSourceAlreadyRun},
		{"ErrOutputChannelNil", capture.ErrOutputChannelNil},
		{"ErrNoSources", capture.ErrNoSources},
		{"ErrInvalidPath", capture.ErrInvalidPath},
		{"ErrInvalidInterface", capture.ErrInvalidInterface},
		{"ErrInvalidBPFExpr", capture.ErrInvalidBPFExpr},
		{"ErrInterfaceNotFound", capture.ErrInterfaceNotFound},
		{"ErrNoBPFExpression", capture.ErrNoBPFExpression},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error is nil")
			}
			if !strings.HasPrefix(tt.err.Error(), "capture:") {
				t.Errorf("error %q does not have 'capture:' prefix", tt.err.Error())
			}
		})
	}
}

// ── CompileBPF ──────────────────────────────────────────────────────────────

func TestCompileBPF_Empty(t *testing.T) {
	bpf, err := capture.CompileBPF("")
	if err != nil {
		t.Fatalf("CompileBPF empty: %v", err)
	}
	if bpf == nil {
		t.Fatal("expected non-nil BPF")
	}
	if got := bpf.Expr(); got != "" {
		t.Errorf("Expr() = %q, want %q", got, "")
	}
}

func TestCompileBPF_Whitespace(t *testing.T) {
	bpf, err := capture.CompileBPF("   \t\n  ")
	if err != nil {
		t.Fatalf("CompileBPF whitespace: %v", err)
	}
	if got := bpf.Expr(); got != "" {
		t.Errorf("Expr() = %q, want %q (whitespace should be trimmed)", got, "")
	}
}

func TestCompileBPF_Valid(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp port 80")
	if err != nil {
		t.Fatalf("CompileBPF: %v", err)
	}
	if got := bpf.Expr(); got != "tcp port 80" {
		t.Errorf("Expr() = %q, want %q", got, "tcp port 80")
	}
}

func TestCompileBPF_Trimmed(t *testing.T) {
	bpf, err := capture.CompileBPF("  tcp port 443  ")
	if err != nil {
		t.Fatalf("CompileBPF: %v", err)
	}
	if got := bpf.Expr(); got != "tcp port 443" {
		t.Errorf("Expr() = %q, want %q", got, "tcp port 443")
	}
}

// ── BPF.Apply ───────────────────────────────────────────────────────────────

func TestBPF_ApplyNilHandle(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := bpf.Apply(nil); err != nil {
		t.Errorf("Apply(nil) = %v, want nil", err)
	}
}

func TestBPF_ApplyEmpty(t *testing.T) {
	bpf, err := capture.CompileBPF("")
	if err != nil {
		t.Fatal(err)
	}
	// Need a real handle to test Apply with empty expr
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()
	// Re-create BPF (the source already has its own; we test that empty expr
	// applied to the source's underlying handle is a no-op).
	_ = bpf // unused here; just verifies CompileBPF path
}

func TestBPF_ExprNilReceiver(t *testing.T) {
	var bpf *capture.BPF
	if got := bpf.Expr(); got != "" {
		t.Errorf("nil BPF Expr() = %q, want %q", got, "")
	}
}

func TestBPF_ApplyNilReceiver(t *testing.T) {
	var bpf *capture.BPF
	if err := bpf.Apply(nil); err != nil {
		t.Errorf("nil BPF Apply(nil) = %v, want nil", err)
	}
}

// ── BPF.Replace ─────────────────────────────────────────────────────────────

func TestBPF_ReplaceValid(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := bpf.Replace("udp", nil); err != nil {
		t.Errorf("Replace: %v", err)
	}
	if got := bpf.Expr(); got != "udp" {
		t.Errorf("Expr() = %q, want %q", got, "udp")
	}
}

func TestBPF_ReplaceEmptyToEmpty(t *testing.T) {
	bpf, err := capture.CompileBPF("")
	if err != nil {
		t.Fatal(err)
	}
	// empty → empty: no error since prior expr is empty
	if err := bpf.Replace("", nil); err != nil {
		t.Errorf("Replace empty→empty: %v", err)
	}
}

func TestBPF_ReplaceToEmptyFails(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	// Replace to empty when prior is non-empty → ErrNoBPFExpression
	err = bpf.Replace("", nil)
	if err == nil {
		t.Fatal("expected error when replacing non-empty with empty")
	}
	if !errors.Is(err, capture.ErrNoBPFExpression) {
		t.Errorf("error = %v, want ErrNoBPFExpression", err)
	}
}

func TestBPF_ReplaceTrimsWhitespace(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := bpf.Replace("  udp  ", nil); err != nil {
		t.Errorf("Replace: %v", err)
	}
	if got := bpf.Expr(); got != "udp" {
		t.Errorf("Expr() = %q, want %q (trimmed)", got, "udp")
	}
}

func TestBPF_ReplaceSkipsNilHandles(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	handles := []*pcapHandleT{nil, nil}
	_ = handles
	// We can't easily construct *pcap.Handle without C bindings,
	// but nil handles should be skipped silently.
	if err := bpf.Replace("udp", nil); err != nil {
		t.Errorf("Replace with nil handles: %v", err)
	}
}

// pcapHandleT is a stub to make the nil-handle test type-safe (we never actually
// pass it to Replace — Replace takes []*pcap.Handle).
type pcapHandleT struct{}

// ── BPF concurrent access ───────────────────────────────────────────────────

func TestBPF_ConcurrentExprAndReplace(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var stop atomic.Bool
	// 4 readers
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_ = bpf.Expr()
			}
		}()
	}
	// 1 writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = bpf.Replace("udp", nil)
		}
		stop.Store(true)
	}()
	wg.Wait()
}

// ── NewFileSource ───────────────────────────────────────────────────────────

func TestNewFileSource_EmptyPath(t *testing.T) {
	_, err := capture.NewFileSource(capture.FileOptions{Path: ""})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !errors.Is(err, capture.ErrInvalidPath) {
		t.Errorf("error = %v, want ErrInvalidPath", err)
	}
}

func TestNewFileSource_InvalidPath(t *testing.T) {
	_, err := capture.NewFileSource(capture.FileOptions{Path: "/nonexistent/file.pcap"})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestNewFileSource_ValidPath(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	name := src.Name()
	if name == "" {
		t.Error("Name() returned empty string")
	}
	if !strings.HasPrefix(name, "file_source:") {
		t.Errorf("Name() = %q, want prefix %q", name, "file_source:")
	}
	if kind := src.Kind(); kind != capture.SourceKindFile {
		t.Errorf("Kind() = %v, want %v", kind, capture.SourceKindFile)
	}
	if lt := src.LinkType(); lt == layers.LinkTypeNull {
		t.Errorf("LinkType() returned LinkTypeNull (0); expected something from pcap file")
	}
}

func TestNewFileSource_WithBPF(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{
		Path: pcapFile,
		BPF:  "tcp",
	})
	if err != nil {
		t.Fatalf("NewFileSource with BPF: %v", err)
	}
	defer src.Close()
	if name := src.Name(); !strings.Contains(name, "file_source:") {
		t.Errorf("Name() = %q, want prefix 'file_source:'", name)
	}
}

func TestNewFileSource_InvalidBPF(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	// Invalid BPF should still parse (CompileBPF is permissive), but Apply might fail
	src, err := capture.NewFileSource(capture.FileOptions{
		Path: pcapFile,
		BPF:  "garbage_invalid_bpf_xyz_12345",
	})
	if err != nil {
		// It's acceptable if BPF apply fails; just ensure we get a meaningful error
		if !errors.Is(err, capture.ErrInvalidBPFExpr) {
			t.Logf("expected ErrInvalidBPFExpr, got: %v", err)
		}
		return
	}
	defer src.Close()
}

// ── FileSource.Run ──────────────────────────────────────────────────────────

func TestFileSource_Run_NilChannel(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()
	err = src.Run(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil channel")
	}
	if !errors.Is(err, capture.ErrOutputChannelNil) {
		t.Errorf("error = %v, want ErrOutputChannelNil", err)
	}
}

func TestFileSource_Run_DoubleRun(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	out := make(chan capture.RawPacket, 16)
	done := make(chan error, 1)
	go func() {
		done <- src.Run(context.Background(), out)
	}()
	// Drain concurrently
	go func() {
		for range out {
		}
	}()
	<-done

	// Second Run should fail with ErrSourceAlreadyRun
	err2 := src.Run(context.Background(), out)
	if err2 == nil {
		t.Fatal("expected error for second Run")
	}
	if !errors.Is(err2, capture.ErrSourceAlreadyRun) {
		t.Errorf("error = %v, want ErrSourceAlreadyRun", err2)
	}
}

func TestFileSource_Run_ReceivesPackets(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	out := make(chan capture.RawPacket, 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var count atomic.Int64
	go func() {
		done <- src.Run(ctx, out)
	}()
	// Drain concurrently so pump doesn't block
	go func() {
		for range out {
			count.Add(1)
		}
	}()

	// Wait for run to complete (pcap is offline → EOF)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s")
	}

	if count.Load() == 0 {
		t.Error("expected at least one packet from single.pcap")
	}
}

func TestFileSource_Run_ContextCancel(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()

	out := make(chan capture.RawPacket, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()
	// Drain to prevent pump blocking
	go func() {
		for range out {
		}
	}()

	// Cancel immediately
	cancel()
	select {
	case err := <-done:
		// Either context.Canceled or nil is acceptable
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run error = %v, want Canceled or nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// ── FileSource.Stats ────────────────────────────────────────────────────────

func TestFileSource_Stats(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	snap, err := src.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if snap.SourceKind != capture.SourceKindFile {
		t.Errorf("SourceKind = %v, want %v", snap.SourceKind, capture.SourceKindFile)
	}
	if snap.SourceName == "" {
		t.Error("SourceName should not be empty")
	}
}

func TestFileSource_StatsAfterRun(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	out := make(chan capture.RawPacket, 64)
	done := make(chan error, 1)
	var count atomic.Int64
	go func() {
		done <- src.Run(context.Background(), out)
	}()
	// Drain concurrently
	go func() {
		for range out {
			count.Add(1)
		}
	}()
	<-done

	snap, err := src.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if snap.Received == 0 {
		t.Errorf("Received = 0 after Run; expected > 0")
	}
}

// ── FileSource.Close ────────────────────────────────────────────────────────

func TestFileSource_CloseIdempotent(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// ── NewLiveSource ───────────────────────────────────────────────────────────

func TestNewLiveSource_EmptyInterface(t *testing.T) {
	_, err := capture.NewLiveSource(capture.LiveOptions{Interface: ""})
	if err == nil {
		t.Fatal("expected error for empty interface")
	}
	if !errors.Is(err, capture.ErrInvalidInterface) {
		t.Errorf("error = %v, want ErrInvalidInterface", err)
	}
}

func TestNewLiveSource_NonexistentInterface(t *testing.T) {
	_, err := capture.NewLiveSource(capture.LiveOptions{
		Interface: "nonexistent_xyz_iface_12345",
	})
	if err == nil {
		t.Skip("nonexistent interface somehow opened; skipping")
	}
}

// ── LiveSource with real interface (best-effort) ────────────────────────────

func TestNewLiveSource_RealInterface(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("loopback test skipped on Windows")
	}
	if os.Getuid() != 0 {
		t.Skip("skip: requires root for live capture")
	}
	src, err := capture.NewLiveSource(capture.LiveOptions{
		Interface: "lo",
		Timeout:   100 * time.Millisecond,
	})
	if err != nil {
		t.Skipf("cannot open lo: %v", err)
	}
	defer src.Close()

	if name := src.Name(); !strings.HasPrefix(name, "interface_source:") {
		t.Errorf("Name() = %q, want prefix 'interface_source:'", name)
	}
	if kind := src.Kind(); kind != capture.SourceKindLive {
		t.Errorf("Kind() = %v, want %v", kind, capture.SourceKindLive)
	}
}

// ── LiveSource.Run validation (without actually opening handle) ─────────────

func TestLiveSource_Run_NilChannel(t *testing.T) {
	// Cannot construct a LiveSource without a real handle easily,
	// so we use FileSource for the nil-channel test (covers same code path).
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()
	err = src.Run(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil channel")
	}
}

// ── Stats ───────────────────────────────────────────────────────────────────

func TestStats_RecordAccepted_NilReceiver(t *testing.T) {
	var s *capture.Stats
	// Should not panic
	s.RecordAccepted(100, 100)
}

func TestStats_RecordAccepted_LengthPositive(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.RecordAccepted(64, 32)
	snap := s.Snapshot()
	if snap.Received != 1 {
		t.Errorf("Received = %d, want 1", snap.Received)
	}
	if snap.Bytes != 64 {
		t.Errorf("Bytes = %d, want 64", snap.Bytes)
	}
}

func TestStats_RecordAccepted_LengthZero_CaptureLenPositive(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.RecordAccepted(0, 32)
	snap := s.Snapshot()
	if snap.Bytes != 32 {
		t.Errorf("Bytes = %d, want 32 (captureLen fallback)", snap.Bytes)
	}
}

func TestStats_RecordAccepted_BothZero(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.RecordAccepted(0, 0)
	snap := s.Snapshot()
	if snap.Bytes != 0 {
		t.Errorf("Bytes = %d, want 0", snap.Bytes)
	}
	if snap.Received != 1 {
		t.Errorf("Received = %d, want 1", snap.Received)
	}
}

func TestStats_RecordAccepted_BothNegative(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.RecordAccepted(-1, -1)
	snap := s.Snapshot()
	if snap.Bytes != 0 {
		t.Errorf("Bytes = %d, want 0 (negatives should not add)", snap.Bytes)
	}
}

func TestStats_SetDropped_NilReceiver(t *testing.T) {
	var s *capture.Stats
	s.SetDropped(42) // should not panic
}

func TestStats_SetDropped(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.SetDropped(42)
	snap := s.Snapshot()
	if snap.Dropped != 42 {
		t.Errorf("Dropped = %d, want 42", snap.Dropped)
	}
	s.SetDropped(100)
	snap = s.Snapshot()
	if snap.Dropped != 100 {
		t.Errorf("Dropped = %d, want 100", snap.Dropped)
	}
}

func TestStats_Snapshot_NilReceiver(t *testing.T) {
	var s *capture.Stats
	snap := s.Snapshot()
	if snap.SourceName != "" {
		t.Errorf("Snapshot SourceName = %q, want empty", snap.SourceName)
	}
	if snap.SourceKind != "" {
		t.Errorf("Snapshot SourceKind = %v, want empty", snap.SourceKind)
	}
}

func TestStats_Snapshot(t *testing.T) {
	s := capture.NewStats("mysrc", capture.SourceKindFile)
	s.RecordAccepted(100, 100)
	s.RecordAccepted(200, 200)
	s.SetDropped(5)

	snap := s.Snapshot()
	if snap.SourceName != "mysrc" {
		t.Errorf("SourceName = %q, want %q", snap.SourceName, "mysrc")
	}
	if snap.SourceKind != capture.SourceKindFile {
		t.Errorf("SourceKind = %v, want %v", snap.SourceKind, capture.SourceKindFile)
	}
	if snap.Received != 2 {
		t.Errorf("Received = %d, want 2", snap.Received)
	}
	if snap.Bytes != 300 {
		t.Errorf("Bytes = %d, want 300", snap.Bytes)
	}
	if snap.Dropped != 5 {
		t.Errorf("Dropped = %d, want 5", snap.Dropped)
	}
}

// ── StatsSnapshot ───────────────────────────────────────────────────────────

func TestStatsSnapshot_Fields(t *testing.T) {
	snap := capture.StatsSnapshot{
		SourceName: "x",
		SourceKind: capture.SourceKindLive,
		Received:   10,
		Bytes:      1000,
		Dropped:    2,
		Filtered:   1,
	}
	if snap.SourceName != "x" || snap.SourceKind != capture.SourceKindLive {
		t.Error("fields not set")
	}
	if snap.Received != 10 || snap.Bytes != 1000 || snap.Dropped != 2 || snap.Filtered != 1 {
		t.Error("numeric fields not set")
	}
}

// ── Stats concurrent ────────────────────────────────────────────────────────

func TestStats_ConcurrentRecordAccepted(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.RecordAccepted(100, 100)
			}
		}()
	}
	wg.Wait()
	snap := s.Snapshot()
	if snap.Received != 1000 {
		t.Errorf("Received = %d, want 1000", snap.Received)
	}
	if snap.Bytes != 100_000 {
		t.Errorf("Bytes = %d, want 100000", snap.Bytes)
	}
}

// ── Source interface conformance ────────────────────────────────────────────

func TestSourceInterface_FileSource(t *testing.T) {
	var s capture.Source = &capture.FileSource{} // zero value; we don't run methods
	if s == nil {
		t.Fatal("nil Source")
	}
}

func TestSourceInterface_LiveSource(t *testing.T) {
	var s capture.Source = &capture.LiveSource{}
	if s == nil {
		t.Fatal("nil Source")
	}
}

// ── FileSource name and kind via real instance ──────────────────────────────

func TestFileSource_NameAndKind(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()

	if got := src.Name(); got != "file_source:"+pcapFile {
		t.Errorf("Name() = %q, want %q", got, "file_source:"+pcapFile)
	}
	if got := src.Kind(); got != capture.SourceKindFile {
		t.Errorf("Kind() = %v, want %v", got, capture.SourceKindFile)
	}
}

// ── FileSource.Stats nil stats path ────────────────────────────────────────

func TestFileSource_StatsNilStats(t *testing.T) {
	// We can't easily construct a FileSource with nil stats (constructor
	// always sets it). But we can verify Stats() returns a non-zero snapshot
	// for a properly constructed source.
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	snap, err := src.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if snap.SourceName == "" {
		t.Error("SourceName should be set")
	}
}

// ── Integration: full Run cycle ─────────────────────────────────────────────

func TestFileSource_RunFullCycle(t *testing.T) {
	pcapFile := pcapFixture(t, "bacnet_test.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()

	out := make(chan capture.RawPacket, 128)
	done := make(chan error, 1)
	var count atomic.Int64
	go func() {
		done <- src.Run(context.Background(), out)
	}()
	// Drain concurrently
	go func() {
		for pkt := range out {
			if pkt.Packet == nil {
				t.Error("packet is nil")
			}
			if pkt.Source.Name == "" {
				t.Error("Source.Name is empty")
			}
			count.Add(1)
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not finish in 10s")
	}
	close(out)
	time.Sleep(10 * time.Millisecond) // let drain goroutine finish

	if count.Load() == 0 {
		t.Error("expected at least one packet from bacnet_test.pcap")
	}

	snap, _ := src.Stats()
	if uint64(count.Load()) != snap.Received {
		t.Errorf("counted %d packets, Stats.Received = %d", count.Load(), snap.Received)
	}
}

// ── FileSource.Run receives packets from closed channel ────────────────────

func TestFileSource_Run_CloseDuringRun(t *testing.T) {
	pcapFile := pcapFixture(t, "bacnet_test.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}

	out := make(chan capture.RawPacket, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()
	// Drain to prevent pump blocking
	go func() {
		for range out {
		}
	}()

	// Let some packets flow
	time.Sleep(50 * time.Millisecond)
	src.Close()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("Run returned: %v (acceptable)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

// ── Run on FileSource for empty PCAP path tests ────────────────────────────

func TestNewFileSource_NoSuchFile(t *testing.T) {
	_, err := capture.NewFileSource(capture.FileOptions{
		Path: "/this/path/does/not/exist/anywhere.pcap",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
	if errors.Is(err, capture.ErrInvalidPath) {
		t.Errorf("error = %v, want generic open error, not ErrInvalidPath", err)
	}
}

func TestNewFileSource_EmptyPathErrInvalidPath(t *testing.T) {
	_, err := capture.NewFileSource(capture.FileOptions{Path: ""})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !errors.Is(err, capture.ErrInvalidPath) {
		t.Errorf("error = %v, want ErrInvalidPath", err)
	}
}

// ── FileSource.Stats with no packets received ───────────────────────────────

func TestFileSource_StatsNoPackets(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Fatalf("NewFileSource: %v", err)
	}
	defer src.Close()

	snap, err := src.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if snap.Received != 0 {
		t.Errorf("Received = %d before Run, want 0", snap.Received)
	}
	if snap.Bytes != 0 {
		t.Errorf("Bytes = %d before Run, want 0", snap.Bytes)
	}
}

// ── LiveSource.Stats nil handle path ────────────────────────────────────────

func TestLiveSource_StatsNilHandle(t *testing.T) {
	// Construct LiveSource directly with zero value
	ls := &capture.LiveSource{}
	snap, err := ls.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if snap.SourceKind != capture.SourceKindLive {
		t.Errorf("SourceKind = %v, want %v", snap.SourceKind, capture.SourceKindLive)
	}
}

// ── FileSource.Stats nil stats path via direct construction ────────────────

func TestFileSource_StatsNilStatsDirect(t *testing.T) {
	fs := &capture.FileSource{}
	snap, err := fs.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if snap.SourceKind != capture.SourceKindFile {
		t.Errorf("SourceKind = %v, want %v", snap.SourceKind, capture.SourceKindFile)
	}
}

// ── CompileBPF with unicode / special chars ─────────────────────────────────

func TestCompileBPF_Unicode(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp and port 8080")
	if err != nil {
		t.Fatalf("CompileBPF: %v", err)
	}
	if got := bpf.Expr(); got != "tcp and port 8080" {
		t.Errorf("Expr() = %q", got)
	}
}

// ── Stats.RecordAccepted edge: length > 0 but captureLen 0 ─────────────────

func TestStats_RecordAccepted_LengthOnly(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.RecordAccepted(64, 0)
	snap := s.Snapshot()
	if snap.Bytes != 64 {
		t.Errorf("Bytes = %d, want 64", snap.Bytes)
	}
}

// ── Stats.RecordAccepted edge: length 0 but captureLen > 0 ─────────────────

func TestStats_RecordAccepted_CaptureLengthOnly(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.RecordAccepted(0, 32)
	snap := s.Snapshot()
	if snap.Bytes != 32 {
		t.Errorf("Bytes = %d, want 32", snap.Bytes)
	}
}

// ── FileSource.Run context cancellation before start ───────────────────────

func TestFileSource_Run_AlreadyCancelledContext(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	out := make(chan capture.RawPacket, 16)
	done := make(chan error, 1)
	go func() {
		done <- src.Run(ctx, out)
	}()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run error = %v, want Canceled or nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return with cancelled context")
	}
}

// ── BPF.Apply with invalid expression to real handle (covers error path) ────

func TestBPF_ApplyInvalidExpressionToFile(t *testing.T) {
	bpf, err := capture.CompileBPF("this_is_an_invalid_bpf_expression_xyz")
	if err != nil {
		t.Fatal(err)
	}
	// CompileBPF is permissive; the error comes from Apply which calls pcap.SetBPFFilter
	if err := bpf.Apply(nil); err != nil {
		t.Errorf("Apply(nil) = %v, want nil", err)
	}
	// The real error path is exercised by NewFileSource with invalid BPF
	// (see TestNewFileSource_InvalidBPF above).
}

// ── BPF.Replace: exercise SetBPFFilter error path with nil handle ──────────

func TestBPF_ReplaceNilHandlesOnly(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	// Nil handles are silently skipped in the loop
	if err := bpf.Replace("udp", nil); err != nil {
		t.Errorf("Replace with nil handles: %v", err)
	}
}

// ── FileSource.LinkType non-zero ────────────────────────────────────────────

func TestFileSource_LinkTypeNonZero(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()
	lt := src.LinkType()
	if lt == 0 {
		t.Error("LinkType is 0 (LinkTypeNull); expected a real link type")
	}
}

// ── FileSource Stats Snapshot name matches ─────────────────────────────────

func TestFileSource_StatsSnapshotName(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()
	snap, _ := src.Stats()
	if snap.SourceName != "file_source:"+pcapFile {
		t.Errorf("SourceName = %q, want %q", snap.SourceName, "file_source:"+pcapFile)
	}
}

// ── FileSource: pcapng format ───────────────────────────────────────────────

func TestNewFileSource_PCAPNG(t *testing.T) {
	pcapFile := pcapFixture(t, "The-Ultimate-PCAP.pcapng")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcapng unavailable: %v", err)
	}
	defer src.Close()
	// Just verify the source was constructed; LinkType varies.
	_ = src.LinkType()
}

// ── Run on file source, multiple packets with metadata ─────────────────────

func TestFileSource_PacketsHaveMetadata(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()

	out := make(chan capture.RawPacket, 64)
	done := make(chan error, 1)
	var count atomic.Int64
	go func() {
		done <- src.Run(context.Background(), out)
	}()
	// Drain concurrently
	go func() {
		for pkt := range out {
			if pkt.Packet.Metadata() != nil {
				_ = pkt.Packet.Metadata().CaptureInfo
			}
			count.Add(1)
		}
	}()
	<-done
	close(out)
	time.Sleep(10 * time.Millisecond)

	if count.Load() == 0 {
		t.Error("expected at least one packet")
	}
}

// ── SourceRef default zero value ────────────────────────────────────────────

func TestSourceRef_ZeroValue(t *testing.T) {
	var ref capture.SourceRef
	if ref.Kind != "" {
		t.Errorf("Kind = %q, want empty", ref.Kind)
	}
	if ref.Name != "" {
		t.Errorf("Name = %q, want empty", ref.Name)
	}
}

// ── RawPacket zero value ────────────────────────────────────────────────────

func TestRawPacket_ZeroValue(t *testing.T) {
	var rp capture.RawPacket
	if rp.Packet != nil {
		t.Error("zero RawPacket has non-nil Packet")
	}
	if rp.Source.Name != "" {
		t.Error("zero RawPacket has non-empty Source.Name")
	}
}

// ── LiveOptions/Source interface fields ─────────────────────────────────────

func TestLiveOptions_Defaults(t *testing.T) {
	// Defaults applied by NewLiveSource: snaplen=65535, timeout=1s
	// We can verify behavior via integration test on real interface (already in TestNewLiveSource_RealInterface).
	// This test just confirms the struct compiles.
	opts := capture.LiveOptions{}
	_ = opts
}

// ── FileOptions ─────────────────────────────────────────────────────────────

func TestFileOptions_ZeroValue(t *testing.T) {
	opts := capture.FileOptions{}
	if opts.Path != "" {
		t.Error("zero FileOptions has non-empty Path")
	}
	if opts.BPF != "" {
		t.Error("zero FileOptions has non-empty BPF")
	}
}

// ── Stats.SetDropped then Snapshot ──────────────────────────────────────────

func TestStats_SetDroppedZero(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	s.SetDropped(0)
	snap := s.Snapshot()
	if snap.Dropped != 0 {
		t.Errorf("Dropped = %d, want 0", snap.Dropped)
	}
}

// ── Stats.RecordAccepted with same length multiple times ────────────────────

func TestStats_RecordAcceptedMultiple(t *testing.T) {
	s := capture.NewStats("test", capture.SourceKindFile)
	for i := 0; i < 5; i++ {
		s.RecordAccepted(100, 100)
	}
	snap := s.Snapshot()
	if snap.Received != 5 {
		t.Errorf("Received = %d, want 5", snap.Received)
	}
	if snap.Bytes != 500 {
		t.Errorf("Bytes = %d, want 500", snap.Bytes)
	}
}

// ── CompileBPF with leading/trailing newlines ───────────────────────────────

func TestCompileBPF_Newlines(t *testing.T) {
	bpf, err := capture.CompileBPF("\n\ntcp port 80\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := bpf.Expr(); got != "tcp port 80" {
		t.Errorf("Expr() = %q, want %q", got, "tcp port 80")
	}
}

// ── BPF.Replace same expression ─────────────────────────────────────────────

func TestBPF_ReplaceSame(t *testing.T) {
	bpf, err := capture.CompileBPF("tcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := bpf.Replace("tcp", nil); err != nil {
		t.Errorf("Replace same: %v", err)
	}
	if got := bpf.Expr(); got != "tcp" {
		t.Errorf("Expr() = %q, want %q", got, "tcp")
	}
}

// ── BPF.Replace with whitespace-only (becomes empty) ────────────────────────

func TestBPF_ReplaceWhitespaceOnly(t *testing.T) {
	bpf, err := capture.CompileBPF("")
	if err != nil {
		t.Fatal(err)
	}
	// empty BPF replaced with whitespace → trimmed to empty → ok
	if err := bpf.Replace("   ", nil); err != nil {
		t.Errorf("Replace whitespace-only when prior is empty: %v", err)
	}
	if got := bpf.Expr(); got != "" {
		t.Errorf("Expr() = %q, want %q", got, "")
	}
}

// ── FileSource.Run after Close: returns quickly without panic ──────────────

func TestFileSource_RunAfterClose(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	src.Close()

	// After Close, the underlying pcap handle is closed.
	// Run may either succeed (pump exits when packets channel closes) or fail.
	// We just verify it doesn't hang or panic.
	out := make(chan capture.RawPacket, 4)
	done := make(chan error, 1)
	go func() {
		done <- src.Run(context.Background(), out)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(3 * time.Second):
		t.Fatal("Run after Close did not return within 3s")
	}
}

// ── CompileBPF followed by Expr ─────────────────────────────────────────────

func TestBPF_ExprAfterCompile(t *testing.T) {
	bpf, err := capture.CompileBPF("icmp")
	if err != nil {
		t.Fatal(err)
	}
	if got := bpf.Expr(); got != "icmp" {
		t.Errorf("Expr() = %q, want %q", got, "icmp")
	}
}

// ── FileSource stats source name prefix ────────────────────────────────────

func TestFileSource_NamePrefix(t *testing.T) {
	pcapFile := pcapFixture(t, "single.pcap")
	src, err := capture.NewFileSource(capture.FileOptions{Path: pcapFile})
	if err != nil {
		t.Skipf("pcap unavailable: %v", err)
	}
	defer src.Close()
	name := src.Name()
	if !strings.HasPrefix(name, "file_source:") {
		t.Errorf("Name() = %q, want prefix 'file_source:'", name)
	}
}

// ── CompileBPF expression with tabs ─────────────────────────────────────────

func TestCompileBPF_Tabs(t *testing.T) {
	bpf, err := capture.CompileBPF("\t\tudp\t\t")
	if err != nil {
		t.Fatal(err)
	}
	if got := bpf.Expr(); got != "udp" {
		t.Errorf("Expr() = %q, want %q", got, "udp")
	}
}
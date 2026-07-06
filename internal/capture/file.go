package capture

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type FileSource struct {
	sourcePath string
	bpfExpr    string
	handle     *pcap.Handle
	linkType   layers.LinkType
	sourceName string

	stats *Stats

	mu         sync.Mutex
	runStarted bool

	closeOnce sync.Once
	closed    chan struct{}
	runDone   chan struct{}
}

type FileOptions struct {
	Path string
	BPF  string
}

var _ Source = (*FileSource)(nil)

func NewFileSource(opts FileOptions) (*FileSource, error) {
	if opts.Path == "" {
		return nil, ErrInvalidPath
	}
	handle, err := pcap.OpenOffline(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("capture: open offline %q: %w", opts.Path, err)
	}
	bpf, err := CompileBPF(opts.BPF)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("capture: compile BPF: %w", err)
	}
	if err := bpf.Apply(handle); err != nil {
		handle.Close()
		return nil, fmt.Errorf("capture: apply BPF: %w", err)
	}
	name := "file_source:" + opts.Path
	return &FileSource{
		sourcePath: opts.Path,
		bpfExpr:    opts.BPF,
		handle:     handle,
		linkType:   handle.LinkType(),
		sourceName: name,
		stats:      NewStats(name, SourceKindFile),
		closed:     make(chan struct{}),
		runDone:    make(chan struct{}),
	}, nil
}

func (f *FileSource) Name() string              { return f.sourceName }
func (f *FileSource) Kind() SourceKind          { return SourceKindFile }
func (f *FileSource) LinkType() layers.LinkType { return f.linkType }


func (f *FileSource) Close() error {
	f.closeOnce.Do(func() {
		if f.handle != nil {
			f.handle.Close()
		}
		close(f.closed)
	})
	select {
	case <-f.runDone:
	case <-defaultCloseWait():
	}
	return nil
}

func (f *FileSource) Run(ctx context.Context, out chan<- RawPacket) error {
	if out == nil {
		return ErrOutputChannelNil
	}
	if !f.markRunStarted() {
		return ErrSourceAlreadyRun
	}
	defer f.markRunDone()

	packetSource := gopacket.NewPacketSource(f.handle, f.linkType)
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	return pump(ctx, packetSource.Packets(), f.closed, out,
		SourceRef{Kind: f.Kind(), Name: f.Name()},
		f.stats)
}

func (f *FileSource) Stats() (StatsSnapshot, error) {
	if f.stats == nil {
		return StatsSnapshot{SourceName: f.sourceName, SourceKind: SourceKindFile}, nil
	}
	return f.stats.Snapshot(), nil
}

func (f *FileSource) markRunStarted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runStarted {
		return false
	}
	f.runStarted = true
	return true
}

func (f *FileSource) markRunDone() {
	close(f.runDone)
}
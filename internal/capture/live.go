package capture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type LiveSource struct {
	iface    string
	name     string
	linkType layers.LinkType

	snaplen int32 // snapshot length. default = 65535 (byte) = max Ethernet frame
	promisc bool
	timeout time.Duration // batching
	bpfExpr string

	handle *pcap.Handle
	stats  *Stats

	mu         sync.Mutex
	runStarted bool

	closeOnce sync.Once
	closed    chan struct{}
	runDone   chan struct{}
}

type LiveOptions struct {
	Interface string
	Snaplen   int32         // default 65535
	Promisc   bool          // default false
	Timeout   time.Duration // default 1s
	BPF       string   
}

var _ Source = (*LiveSource)(nil)

func NewLiveSource(opts LiveOptions) (*LiveSource, error) {
	if opts.Interface == "" {
		return nil, ErrInvalidInterface
	}

	snaplen := opts.Snaplen
	if snaplen <= 0 {
		snaplen = 65535
	}
	promisc := opts.Promisc
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}

	handle, err := pcap.OpenLive(opts.Interface, snaplen, promisc, timeout)
	if err != nil {
		return nil, fmt.Errorf("capture: open live %q: %w", opts.Interface, err)
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

	name := "interface_source:"+opts.Interface
	return &LiveSource{
		iface:    opts.Interface,
		name:     name,
		linkType: handle.LinkType(),
		snaplen:  snaplen,
		promisc:  promisc,
		timeout:  timeout,
		bpfExpr:  opts.BPF,
		handle:   handle,
		stats:    NewStats(name, SourceKindLive),
		closed:   make(chan struct{}),
		runDone:  make(chan struct{}),
	}, nil
}

func (s *LiveSource) Name() string              { return s.name }
func (s *LiveSource) Kind() SourceKind          { return SourceKindLive }
func (s *LiveSource) LinkType() layers.LinkType { return s.linkType }

func (s *LiveSource) Close() error {
	s.closeOnce.Do(func() {
		if s.handle != nil {
			s.handle.Close()
		}
		close(s.closed)
	})
	select {
	case <-s.runDone:
	case <-defaultCloseWait():
	}
	return nil
}

func (s *LiveSource) Run(ctx context.Context, out chan<- RawPacket) error {
	if out == nil {
		return ErrOutputChannelNil
	}
	if !s.markRunStarted() {
		return ErrSourceAlreadyRun
	}
	defer s.markRunDone()

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	return pump(ctx, packetSource.Packets(), s.closed, out,
		SourceRef{Kind: s.Kind(), Name: s.Name()},
		s.stats)
}

func (s *LiveSource) Stats() (StatsSnapshot, error) {
	if s.stats == nil {
		return StatsSnapshot{SourceName: s.name, SourceKind: SourceKindLive}, nil
	}
	snap := s.stats.Snapshot()
	if s.handle != nil {
		if ps, err := s.handle.Stats(); err == nil {
			snap.Dropped = uint64(ps.PacketsDropped + ps.PacketsIfDropped)
			s.stats.SetDropped(snap.Dropped)
		}
	}
	return snap, nil
}

func (s *LiveSource) markRunStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runStarted {
		return false
	}
	s.runStarted = true
	return true
}

func (s *LiveSource) markRunDone() {
	close(s.runDone)
}
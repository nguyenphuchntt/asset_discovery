package capture

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	ErrOutputChanelNotFound = errors.New("Output channel not found")
	ErrSourceAlreadyRun = errors.New("Source is already run")
)

type FileSource struct {
	sourcePath string
	handle *pcap.Handle
	linkType layers.LinkType
	sourceName string

	mu sync.Mutex
	stats CaptureStats

	runStarted bool
	closed chan struct{}
	closeOnce sync.Once
}

var _ Source = (*FileSource)(nil)

func NewFileSource(sourcePath string) (*FileSource, error) {
	handle, err := pcap.OpenOffline(sourcePath)
	if err != nil {
		return nil, err
	}

	f := &FileSource{
		sourcePath: sourcePath,
		sourceName: sourcePath,
		handle:     handle,
		linkType:   handle.LinkType(),
		closed:     make(chan struct{}),
		stats: CaptureStats{
			SourceName: sourcePath,
			SourceKind: SourceKindFile,
		},
	}
 
	return f, nil
}

func (f *FileSource) Name() string {
	return f.sourceName
}

func (f *FileSource) Kind() SourceKind {
	return SourceKindFile
}

func (f *FileSource) LinkType() layers.LinkType {
	return f.linkType
}

func (f *FileSource) Close() error {
	f.closeHandle()
	return nil
}

func (f *FileSource) closeHandle() {
	f.closeOnce.Do(func() {
		close(f.closed)
		f.handle.Close()
	})
}

func (f *FileSource) markRunStarted() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.runStarted {
		return ErrSourceAlreadyRun
	}
	f.runStarted = true
	return nil
}

func (f *FileSource) Run(ctx context.Context, out chan<- RawPacket) error {
	if out == nil {
		return ErrOutputChanelNotFound
	}
	if err := f.markRunStarted(); err != nil {
		return err
	}
	defer f.closeHandle()
 
	packetSource := gopacket.NewPacketSource(f.handle, f.linkType)
	packets := packetSource.Packets()
 
	for {
		select {
		case <-ctx.Done(): // context closed
			return ctx.Err()
		case <-f.closed: // file source closed
			return nil
		case packet, ok := <-packets:
			if !ok {
				return nil
			}
			rawPacket := f.newRawPacket(packet)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-f.closed:
				return nil
			case out <- rawPacket:
				f.recordReceived(rawPacket)
			}
		}
	}
}

func (f *FileSource) CaptureStats() (CaptureStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.stats, nil
}

func (f *FileSource) newRawPacket(packet gopacket.Packet) RawPacket {
	capturedAt := time.Now() // fallback
	length := 0
	captureLength := 0
 
	if metadata := packet.Metadata(); metadata != nil {
		captureInfo := metadata.CaptureInfo
		if !captureInfo.Timestamp.IsZero() {
			capturedAt = captureInfo.Timestamp
		}
		length = captureInfo.Length
		captureLength = captureInfo.CaptureLength
	}
 
	return RawPacket{
		Packet:        packet,
		SourceName:    f.sourceName,
		SourceKind:    SourceKindFile,
		CapturedAt:    capturedAt,
		Length:        length,
		CaptureLength: captureLength,
		LinkType:      f.linkType,
	}
}

func (f *FileSource) recordReceived(packet RawPacket) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.stats.Received++
	if packet.Length > 0 {
		f.stats.Bytes += uint64(packet.Length)
		return
	}
	// else
	if packet.CaptureLength > 0 {
		f.stats.Bytes += uint64(packet.CaptureLength)
	}
}
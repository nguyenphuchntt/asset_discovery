// file.go implements offline PCAP capture.
//
// Responsibilities:
// - open a PCAP/PCAPNG file for read-only packet replay;
// - emit every packet into the capture channel;
// - maintain read stats;
// - close handles cleanly at EOF or shutdown;
// - later apply configured BPF when offline filtering is requested.
package capture

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type FileSource struct {
	sourcePath string
	handle     *pcap.Handle
	packets    chan gopacket.Packet

	mu        sync.Mutex
	stats     Stats
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
		handle:     handle,
		packets:    make(chan gopacket.Packet),
	}

	go f.readPackets()

	return f, nil
}

func (f *FileSource) readPackets() {
	defer close(f.packets)
	defer f.closeHandle()

	packetSource := gopacket.NewPacketSource(f.handle, f.handle.LinkType())
	for packet := range packetSource.Packets() {
		f.packets <- packet
		f.mu.Lock()
		f.stats.Received++
		f.mu.Unlock()
	}
}

func (f *FileSource) Packets() <-chan gopacket.Packet {
	return f.packets
}

func (f *FileSource) Stats() (Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.stats, nil
}

func (f *FileSource) Close() error {
	f.closeHandle()
	return nil
}

func (f *FileSource) closeHandle() {
	f.closeOnce.Do(func() {
		f.handle.Close()
	})
}

package capture

import (
	"context"
	"time"

	"github.com/google/gopacket"
)

func pump(
	ctx context.Context,
	packets <-chan gopacket.Packet,
	closed <-chan struct{},
	out chan<- RawPacket,
	ref SourceRef,
	stats *Stats,
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		select { // new packet or terminate
		case <-ctx.Done():
			return ctx.Err()
		case <-closed:
			return nil
		case pkt, ok := <-packets:
			if !ok {
				return nil
			}
			if !isObservable(pkt) {
				continue
			}
			raw := RawPacket{Packet: pkt, Source: ref}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-closed:
				return nil
			case out <- raw:
				length, capLen := packetLengths(pkt)
				stats.RecordAccepted(length, capLen)
			}
		}
	}
}

func isObservable(packet gopacket.Packet) bool {
	if packet == nil {
		return false
	}
	return len(packet.Layers()) > 0
}

func packetLengths(packet gopacket.Packet) (length, captureLength int) {
	if packet == nil {
		return 0, 0
	}
	md := packet.Metadata()
	if md == nil {
		return 0, 0
	}
	return md.CaptureInfo.Length, md.CaptureInfo.CaptureLength
}

const defaultCloseWaitDuration = 2 * time.Second
func defaultCloseWait() <-chan time.Time {
	return time.After(defaultCloseWaitDuration) // wait
}
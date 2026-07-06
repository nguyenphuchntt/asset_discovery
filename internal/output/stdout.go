package output

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"passivediscovery/internal/asset"
)

// StdoutSink prints a human-readable discovery summary to a writer.
// The format uses Unicode box drawing so the output is easy to scan
// in a terminal.
type StdoutSink struct {
	Out io.Writer
}

// NewStdoutSink writes to os.Stdout.
func NewStdoutSink() *StdoutSink {
	return &StdoutSink{Out: os.Stdout}
}

// WriteAssets prints the full asset summary. Events are not printed here;
// the caller can use WriteEvents separately or let the MultiSink handle it.
func (s *StdoutSink) WriteAssets(_ context.Context, snapshots []asset.AssetSnapshot) error {
	s.printSummary(snapshots, nil)
	return nil
}

func (s *StdoutSink) WriteEvents(_ context.Context, events []asset.Event) error {
	// Events are already embedded in WriteAssets via the second argument;
	// this method exists to satisfy the Sink interface. When called alone
	// we print nothing — the full summary is the preferred output path.
	return nil
}

// PrintSummary writes the complete box-drawing summary. Exported so main
// can call it without constructing a full Sink (useful for piping events
// through separately).
func (s *StdoutSink) PrintSummary(snapshots []asset.AssetSnapshot, events []asset.Event) {
	s.printSummary(snapshots, events)
}

func (s *StdoutSink) printSummary(snapshots []asset.AssetSnapshot, events []asset.Event) {
	w := s.Out

	fmt.Fprintln(w)

	// --- header ---
	fmt.Fprintf(w, "=== discovery summary ===\n")

	// count statuses
	byStatus := map[asset.Status]int{}
	for _, snap := range snapshots {
		byStatus[snap.Status]++
	}
	fmt.Fprintf(w, "  assets discovered : %d  (online: %d, offline: %d)\n",
		len(snapshots), byStatus[asset.StatusOnline], byStatus[asset.StatusOffline])

	// count events
	if len(events) > 0 {
		byType := map[asset.EventType]int{}
		for _, e := range events {
			byType[e.Type]++
		}
		fmt.Fprintf(w, "  events emitted    : %d\n", len(events))
		for _, t := range sortedEventTypes(byType) {
			fmt.Fprintf(w, "    %-22s : %d\n", t, byType[t])
		}
	}
	fmt.Fprintln(w)

	// --- per-asset boxes ---
	for _, snap := range snapshots {
		s.printAssetBox(snap)
	}
}

// printAssetBox renders one asset in a Unicode box-drawing frame.
func (s *StdoutSink) printAssetBox(snap asset.AssetSnapshot) {
	w := s.Out

	// Collect all lines first so we can compute max width.
	lines := s.assetLines(snap)

	// Compute inner width = max line content length.
	innerWidth := 0
	for _, l := range lines {
		if l.contentLen > innerWidth {
			innerWidth = l.contentLen
		}
	}
	if innerWidth < 30 {
		innerWidth = 30
	}

	// Header
	title := string(snap.ID)
	status := string(snap.Status)
	headerLeft := "─ " + title + " "
	headerRight := " " + status + " "
	spaceForTitle := innerWidth - len(headerLeft) - len(headerRight)
	if spaceForTitle < 3 {
		spaceForTitle = 3
	}
	fmt.Fprintf(w, "┌%s%s%s┐\n", headerLeft, strings.Repeat("─", spaceForTitle), headerRight)

	// Content lines
	for _, l := range lines {
		pad := innerWidth - l.contentLen
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintf(w, "│ %s%s│\n", l.text, strings.Repeat(" ", pad))
	}

	// Footer
	fmt.Fprintf(w, "└%s┘\n", strings.Repeat("─", innerWidth))
	fmt.Fprintln(w)
}

type line struct {
	text       string
	contentLen int // visible characters (no ANSI)
}

func (s *StdoutSink) assetLines(snap asset.AssetSnapshot) []line {
	var lines []line
	kv := func(key, val string) {
		if val == "" {
			return
		}
		text := key + " : " + val
		lines = append(lines, line{text: text, contentLen: len(text)})
	}

	// --- MAC + Vendor ---
	kv("MAC", formatMAC(snap.MAC))
	kv("Vendor", snap.MACVendor)

	// --- IPs ---
	kv("IPv4", formatIPMap(snap.IPv4s, 4))
	kv("IPv6", formatIPMap(snap.IPv6s, 6))

	// --- Hostnames ---
	if len(snap.Hostnames) > 0 {
		kv("Hostnames", strings.Join(snap.Hostnames, ", "))
	}

	// --- OS / Model / DeviceType ---
	kv("OS", snap.OS)
	kv("Model", snap.Model)
	kv("DeviceType", snap.DeviceType)

	// --- Services ---
	if len(snap.Services) > 0 {
		lines = append(lines, line{text: "Services :", contentLen: len("Services :")})
		for _, svc := range snap.Services {
			lines = append(lines, line{
				text:       "  " + formatService(svc),
				contentLen: 2 + len(formatService(svc)),
			})
		}
	}

	// --- Extras (sorted) ---
	if len(snap.Extra) > 0 {
		lines = append(lines, line{text: "Extras :", contentLen: len("Extras :")})
		for _, k := range sortedKeys(snap.Extra) {
			val := fmt.Sprintf("%v", snap.Extra[k])
			text := "  " + k + " : " + val
			lines = append(lines, line{text: text, contentLen: len(text)})
		}
	}

	// --- Timestamps ---
	tsFmt := "2006-01-02 15:04:05"
	kv("First seen", snap.FirstSeen.Format(tsFmt))
	kv("Last seen", snap.LastSeen.Format(tsFmt))
	kv("Seen count", strconv.FormatUint(snap.SeenCount, 10))

	return lines
}

// --- Formatting helpers ---

func formatMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return ""
	}
	return mac.String()
}

func formatIPMap(m map[string]asset.IPEntry, ver int) string {
	if len(m) == 0 {
		return ""
	}
	// Sort for deterministic output.
	type ipInfo struct {
		ip     string
		active bool
	}
	var ips []ipInfo
	for ip, entry := range m {
		ips = append(ips, ipInfo{ip: ip, active: entry.IsActive})
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].ip < ips[j].ip })

	parts := make([]string, len(ips))
	for i, p := range ips {
		if p.active {
			parts[i] = p.ip + " (active)"
		} else {
			parts[i] = p.ip
		}
	}
	return strings.Join(parts, ", ")
}

func formatService(svc asset.Service) string {
	role := "server"
	if svc.IsClient {
		role = "client"
	}
	text := fmt.Sprintf("%s/%d [%s]", svc.Protocol, svc.Port, role)
	if svc.Name != "" {
		text += "  " + svc.Name
	}
	if svc.Product != "" {
		text += "  " + svc.Product
	}
	if !svc.LastSeen.IsZero() {
		text += "  last " + svc.LastSeen.Format("15:04:05")
	}
	return text
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedEventTypes(m map[asset.EventType]int) []asset.EventType {
	keys := make([]asset.EventType, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
package oui_test

import (
	"testing"

	"passivediscovery/internal/oui"
)

// Lookup.VendorForMAC — covered scenarios:
//   1. Exact prefix match (6-char) → returns vendor
//   2. Longer prefix wins (8-char vs 6-char) → longer match
//   3. No match → empty, false
//   4. Empty MAC → empty, false
//   5. Invalid MAC format → empty, false
//   6. Nil Lookup → empty, false
//   7. MAC prefix with separators (colon, dash, dot) → normalized and matched
//   8. MAC prefix not in table → empty, false
//   9. Multiple entries → correct vendor for each

func TestLookup_ExactMatch(t *testing.T) {
	t.Parallel()
	entries := map[string]string{
		"001A2B": "Apple Inc.",
	}
	l := oui.NewLookup(entries)

	vendor, ok := l.VendorForMAC("00:1A:2B:CC:DD:EE")
	if !ok || vendor != "Apple Inc." {
		t.Errorf("expected Apple Inc., got %q (ok=%v)", vendor, ok)
	}
}

func TestLookup_LongerPrefixWins(t *testing.T) {
	t.Parallel()
	entries := map[string]string{
		"001A":   "Short Vendor",
		"001A2B": "Long Vendor",
	}
	l := oui.NewLookup(entries)

	vendor, ok := l.VendorForMAC("001A2B:CC:DD:EE")
	if !ok || vendor != "Long Vendor" {
		t.Errorf("expected Long Vendor (longest prefix), got %q (ok=%v)", vendor, ok)
	}
}

func TestLookup_NoMatch(t *testing.T) {
	t.Parallel()
	entries := map[string]string{
		"001A2B": "Apple Inc.",
	}
	l := oui.NewLookup(entries)

	_, ok := l.VendorForMAC("FF:FF:FF:00:00:01")
	if ok {
		t.Error("expected no match")
	}
}

func TestLookup_EmptyMAC(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Test"}
	l := oui.NewLookup(entries)

	_, ok := l.VendorForMAC("")
	if ok {
		t.Error("expected no match for empty MAC")
	}
}

func TestLookup_InvalidMACFormat(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Test"}
	l := oui.NewLookup(entries)

	_, ok := l.VendorForMAC("not-a-mac")
	if ok {
		t.Error("expected no match for invalid MAC")
	}
}

func TestLookup_NilLookup(t *testing.T) {
	t.Parallel()
	var l *oui.Lookup
	_, ok := l.VendorForMAC("00:1A:2B:CC:DD:EE")
	if ok {
		t.Error("expected no match for nil Lookup")
	}
}

func TestLookup_ColonSeparator(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Test"}
	l := oui.NewLookup(entries)

	vendor, ok := l.VendorForMAC("00:1a:2b:cc:dd:ee")
	if !ok || vendor != "Test" {
		t.Errorf("expected Test, got %q (ok=%v)", vendor, ok)
	}
}

func TestLookup_DashSeparator(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Test"}
	l := oui.NewLookup(entries)

	vendor, ok := l.VendorForMAC("00-1A-2B-CC-DD-EE")
	if !ok || vendor != "Test" {
		t.Errorf("expected Test, got %q (ok=%v)", vendor, ok)
	}
}

func TestLookup_DotSeparator(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Test"}
	l := oui.NewLookup(entries)

	vendor, ok := l.VendorForMAC("00.1A.2B.CC.DD.EE")
	if !ok || vendor != "Test" {
		t.Errorf("expected Test, got %q (ok=%v)", vendor, ok)
	}
}

func TestLookup_MultipleEntries(t *testing.T) {
	t.Parallel()
	entries := map[string]string{
		"001A2B": "Apple",
		"002A3C": "Google",
		"003A4D": "Microsoft",
	}
	l := oui.NewLookup(entries)

	tests := []struct {
		mac      string
		want     string
	}{
		{"00:1A:2B:00:00:01", "Apple"},
		{"00:2A:3C:00:00:01", "Google"},
		{"00:3A:4D:00:00:01", "Microsoft"},
	}

	for _, tc := range tests {
		vendor, ok := l.VendorForMAC(tc.mac)
		if !ok || vendor != tc.want {
			t.Errorf("MAC %s: expected %q, got %q (ok=%v)", tc.mac, tc.want, vendor, ok)
		}
	}
}

func TestLookup_Len(t *testing.T) {
	t.Parallel()
	l := oui.NewLookup(map[string]string{
		"001A2B": "A",
		"002A3C": "B",
	})
	if got := l.Len(); got != 2 {
		t.Errorf("expected Len()=2, got %d", got)
	}
}

func TestLookup_LenNil(t *testing.T) {
	t.Parallel()
	var l *oui.Lookup
	if got := l.Len(); got != 0 {
		t.Errorf("expected Len()=0 for nil Lookup, got %d", got)
	}
}

func TestLookup_EmptyEntries(t *testing.T) {
	t.Parallel()
	l := oui.NewLookup(map[string]string{})
	if got := l.Len(); got != 0 {
		t.Errorf("expected Len()=0 for empty entries, got %d", got)
	}
}

func TestLookup_EmptyVendorSkipped(t *testing.T) {
	t.Parallel()
	entries := map[string]string{
		"001A2B": "", // empty vendor
	}
	l := oui.NewLookup(entries)
	if l.Len() != 0 {
		t.Errorf("expected empty vendor entry to be skipped")
	}
}

func TestLookup_VendorWithSpaces(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Apple  Inc.  "}
	l := oui.NewLookup(entries)

	vendor, _ := l.VendorForMAC("00:1A:2B:00:00:01")
	// NewLookup normalizes vendor via cleanVendor
	if vendor != "Apple Inc." {
		t.Errorf("expected 'Apple Inc.', got %q", vendor)
	}
}

func TestLookup_ColonlessMAC(t *testing.T) {
	t.Parallel()
	entries := map[string]string{"001A2B": "Test"}
	l := oui.NewLookup(entries)

	// No separators — continuous hex
	vendor, ok := l.VendorForMAC("001A2BCCDDEE")
	if !ok || vendor != "Test" {
		t.Errorf("expected Test for colonless MAC, got %q (ok=%v)", vendor, ok)
	}
}

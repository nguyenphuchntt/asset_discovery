package oui_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"passivediscovery/internal/oui"
)

// ---------- helpers ----------

// errReader errors after returning data
type errReader struct {
	data   []byte
	off    int
	err    error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// ---------- Parse via public API ----------

func TestParse_Empty(t *testing.T) {
	entries, err := oui.Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParse_OnlyComments(t *testing.T) {
	input := "# comment 1\n; comment 2\n// comment 3\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParse_MixedCommentsAndEntries(t *testing.T) {
	input := "# header comment\nMA-L,AA:BB:CC,Cisco,Addr1\n" +
		"; another comment\nMA-L,DD:EE:FF,Nokia,Addr2\n" +
		"// trailing comment\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries["AABBCC"] != "Cisco" {
		t.Errorf("AABBCC: got %q, want Cisco", entries["AABBCC"])
	}
	if entries["DDEEFF"] != "Nokia" {
		t.Errorf("DDEEFF: got %q, want Nokia", entries["DDEEFF"])
	}
}

func TestParse_BlankLines(t *testing.T) {
	input := "\n\nMA-L,AA:BB:CC,Vendor,Addr\n\n\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParse_MalformedLineSkipped(t *testing.T) {
	input := "MA-L,ZZZZZZ,BadVendor,Addr\nMA-L,AA:BB:CC,GoodVendor,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected ParseError, got nil")
	}
	var pe *oui.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if len(pe.Lines) != 1 {
		t.Errorf("expected 1 line error, got %d", len(pe.Lines))
	}
	if pe.Lines[0].Line != 1 {
		t.Errorf("expected line 1, got %d", pe.Lines[0].Line)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(entries))
	}
	if entries["AABBCC"] != "GoodVendor" {
		t.Errorf("expected GoodVendor, got %q", entries["AABBCC"])
	}
}

func TestParse_AllRegistryTypes(t *testing.T) {
	input := "MA-L,AA:BB:CC,VendorL,Addr\n" +
		"MA-M,DD:EE:FF:00,VendorM,Addr\n" +
		"MA-S,11:22:33:44:55:66,VendorS,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries["AABBCC"] != "VendorL" {
		t.Errorf("MA-L: got %q", entries["AABBCC"])
	}
	if entries["DDEEFF00"] != "VendorM" {
		t.Errorf("MA-M: got %q", entries["DDEEFF00"])
	}
	if entries["112233445566"] != "VendorS" {
		t.Errorf("MA-S: got %q", entries["112233445566"])
	}
}

func TestParse_DuplicatePrefix(t *testing.T) {
	input := "MA-L,AA:BB:CC,Vendor1,Addr\nMA-L,AA:BB:CC,Vendor2,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (dup), got %d", len(entries))
	}
	if entries["AABBCC"] != "Vendor2" {
		t.Errorf("expected Vendor2 (last wins), got %q", entries["AABBCC"])
	}
}

func TestParse_PrivateVendorSkipped(t *testing.T) {
	input := "MA-L,AA:BB:CC,Private,Addr\nMA-L,DD:EE:FF,Real Vendor,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if _, ok := entries["AABBCC"]; ok {
		t.Error("Private vendor should be skipped")
	}
}

func TestParse_EmptyAssignment(t *testing.T) {
	input := "MA-L,,Some Vendor,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for empty assignment")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParse_MultipleErrors(t *testing.T) {
	input := "MA-L,ZZZZZZ,Bad1,Addr\nMA-L,GGHHII,Bad2,Addr\nMA-L,AA:BB:CC,Good,Addr\n"
	_, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error")
	}
	var pe *oui.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ParseError, got %T", err)
	}
	if len(pe.Lines) != 2 {
		t.Errorf("expected 2 line errors, got %d", len(pe.Lines))
	}
}

func TestParse_HeaderLineSkipped(t *testing.T) {
	input := "Registry,Assignment,Organization Name,Organization Address\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from header, got %d", len(entries))
	}
}

func TestParse_CRLF(t *testing.T) {
	input := "MA-L,AA:BB:CC,Vendor,Addr\r\nMA-L,DD:EE:FF,Vendor2,Addr\r\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestParse_MixedLineEndings(t *testing.T) {
	input := "MA-L,AA:BB:CC,Vendor1,Addr\nMA-L,DD:EE:FF,Vendor2,Addr\r\nMA-L,11:22:33,Vendor3,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestParse_WrongRegistrySkipped(t *testing.T) {
	input := "MA-O,AA:BB:CC,Vendor,Addr\nMA-X,AA:BB:CC,Vendor2,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (unknown registry), got %d", len(entries))
	}
}

func TestParse_TooShortForRegistry(t *testing.T) {
	input := "one,two\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0, got %d", len(entries))
	}
}

func TestParse_QuotedVendor(t *testing.T) {
	input := `MA-L,AA:BB:CC,"Cisco Systems, Inc.","Some Address"` + "\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries["AABBCC"] != "Cisco Systems, Inc." {
		t.Errorf("got %q, want 'Cisco Systems, Inc.'", entries["AABBCC"])
	}
}

func TestParse_LowercaseRegistry(t *testing.T) {
	input := "ma-l,AA:BB:CC,Vendor,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParse_DashAssignment(t *testing.T) {
	input := "MA-L,AA-BB-CC,Vendor,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries["AABBCC"] != "Vendor" {
		t.Errorf("got %q", entries["AABBCC"])
	}
}

func TestParse_DotAssignment(t *testing.T) {
	input := "MA-L,AA.BB.CC,Vendor,Addr\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries["AABBCC"] != "Vendor" {
		t.Errorf("got %q", entries["AABBCC"])
	}
}

func TestParse_VeryLongLine(t *testing.T) {
	addr := strings.Repeat("A", 10000)
	input := "MA-L,AA:BB:CC,Vendor," + addr + "\n"
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries["AABBCC"] != "Vendor" {
		t.Errorf("expected Vendor, got %q", entries["AABBCC"])
	}
}

// ---------- Scanner error path (currently uncovered) ----------

func TestParse_ScannerError(t *testing.T) {
	// Reader returns valid data then errors on next Read.
	// scanner.Scan returns true for first line, then Read returns error.
	// scanner.Err() returns the error → Parse returns (entries, err)
	r := &errReader{
		data: []byte("MA-L,AA:BB:CC,Vendor,Addr\n"),
		err:  fmt.Errorf("synthetic scanner error"),
	}
	entries, err := oui.Parse(r)
	if err == nil {
		t.Fatal("expected error from scanner")
	}
	if !strings.Contains(err.Error(), "synthetic scanner error") {
		t.Errorf("expected scanner error in message, got %v", err)
	}
	// Partial results: 1 valid entry from before the error
	if len(entries) != 1 {
		t.Errorf("expected 1 partial entry, got %d", len(entries))
	}
	if entries["AABBCC"] != "Vendor" {
		t.Errorf("expected Vendor, got %q", entries["AABBCC"])
	}
}

// ---------- splitRegistryRow error path (currently uncovered) ----------
// CSV reader returns error on unclosed quoted fields or unescaped quotes.

func TestParse_MalformedCSVQuote(t *testing.T) {
	// Unclosed quote triggers csv.Reader.Read() error inside splitRegistryRow.
	// The first part is recognized as MA-L (registry), but CSV parsing fails
	// → splitRegistryRow returns (nil, err) → parseLine returns error.
	input := `MA-L,AA:BB:CC,"unclosed quote,vendor,addr` + "\n"
	_, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error from malformed CSV")
	}
	if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "quote") {
		t.Logf("got error: %v", err)
	}
}

// ---------- ParseError ----------

func TestParseError_Nil(t *testing.T) {
	var pe *oui.ParseError
	if pe.Error() != "" {
		t.Errorf("nil ParseError.Error() should be empty, got %q", pe.Error())
	}
}

func TestParseError_Empty(t *testing.T) {
	pe := &oui.ParseError{}
	if pe.Error() != "" {
		t.Errorf("empty ParseError.Error() should be empty, got %q", pe.Error())
	}
}

func TestParseError_Single(t *testing.T) {
	pe := &oui.ParseError{
		Lines: []oui.LineError{
			{Line: 5, Text: "bad line", Err: errors.New("invalid hex")},
		},
	}
	msg := pe.Error()
	if !strings.Contains(msg, "line 5") {
		t.Errorf("expected 'line 5' in error, got %q", msg)
	}
	if !strings.Contains(msg, "invalid hex") {
		t.Errorf("expected 'invalid hex' in error, got %q", msg)
	}
}

func TestParseError_Multiple(t *testing.T) {
	pe := &oui.ParseError{
		Lines: []oui.LineError{
			{Line: 3, Err: errors.New("err1")},
			{Line: 7, Err: errors.New("err2")},
		},
	}
	msg := pe.Error()
	if !strings.Contains(msg, "2 malformed") {
		t.Errorf("expected '2 malformed' in error, got %q", msg)
	}
	if !strings.Contains(msg, "line 3") {
		t.Errorf("expected 'line 3' in error, got %q", msg)
	}
}

// ---------- NewLookup ----------

func TestNewLookup_Empty(t *testing.T) {
	l := oui.NewLookup(map[string]string{})
	if l.Len() != 0 {
		t.Errorf("expected 0, got %d", l.Len())
	}
}

func TestNewLookup_Nil(t *testing.T) {
	l := oui.NewLookup(nil)
	if l.Len() != 0 {
		t.Errorf("expected 0, got %d", l.Len())
	}
}

func TestNewLookup_ValidEntries(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC": "Cisco",
		"DD:EE:FF": "Nokia",
	}
	l := oui.NewLookup(entries)
	if l.Len() != 2 {
		t.Errorf("expected 2, got %d", l.Len())
	}
}

func TestNewLookup_SkipsExplicitlyEmptyVendor(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC": "Cisco",
		"DD:EE:FF": "",
	}
	l := oui.NewLookup(entries)
	if l.Len() != 1 {
		t.Errorf("expected 1 (skip empty), got %d", l.Len())
	}
}

func TestNewLookup_SkipsInvalidPrefix(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC": "Cisco",
		"GGHHII":   "Bad",  // invalid hex
		"AA:BB":    "Short", // too short
	}
	l := oui.NewLookup(entries)
	if l.Len() != 1 {
		t.Errorf("expected 1 (skip invalid), got %d", l.Len())
	}
}

func TestNewLookup_PrefixLengthsSorted(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC":          "V6",
		"DD:EE:FF:00":       "V8",
		"11:22:33:44:55:66": "V12",
	}
	l := oui.NewLookup(entries)
	// 12-char MAC matches 12-char prefix
	vendor, ok := l.VendorForMAC("11:22:33:44:55:66")
	if !ok {
		t.Fatal("expected match")
	}
	if vendor != "V12" {
		t.Errorf("expected V12 (longest prefix), got %q", vendor)
	}
}

func TestNewLookup_CleansVendor(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC": "  Cisco   Systems  ",
	}
	l := oui.NewLookup(entries)
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok {
		t.Fatal("expected match")
	}
	if vendor != "Cisco Systems" {
		t.Errorf("vendor=%q, want %q", vendor, "Cisco Systems")
	}
}

func TestNewLookup_AllPrefixLengths(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC:DD:EE:FF": "12",
		"AA:BB:CC:DD:EE":    "10",
		"AA:BB:CC:DD":       "8",
		"AA:BB:CC":          "6",
	}
	l := oui.NewLookup(entries)
	if l.Len() != 4 {
		t.Errorf("expected 4, got %d", l.Len())
	}
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok || vendor != "12" {
		t.Errorf("full match: got (%q, %v), want (12, true)", vendor, ok)
	}
	vendor, ok = l.VendorForMAC("AA:BB:CC:DD:00:00")
	if !ok || vendor != "8" {
		t.Errorf("8-char match: got (%q, %v), want (8, true)", vendor, ok)
	}
	vendor, ok = l.VendorForMAC("AA:BB:CC:00:00:00")
	if !ok || vendor != "6" {
		t.Errorf("6-char match: got (%q, %v), want (6, true)", vendor, ok)
	}
}

func TestNewLookup_MultiplePrefixLengths(t *testing.T) {
	entries := map[string]string{
		"AA:BB:CC":          "Short",
		"AA:BB:CC:DD":       "Med",
		"AA:BB:CC:DD:EE:FF": "Long",
	}
	l := oui.NewLookup(entries)
	// Different 12-char MACs to exercise different prefix matches
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok || vendor != "Long" {
		t.Errorf("12-char prefix: got (%q, %v), want (Long, true)", vendor, ok)
	}
	vendor, ok = l.VendorForMAC("AA:BB:CC:DD:11:22")
	if !ok || vendor != "Med" {
		t.Errorf("8-char prefix: got (%q, %v), want (Med, true)", vendor, ok)
	}
	vendor, ok = l.VendorForMAC("AA:BB:CC:11:22:33")
	if !ok || vendor != "Short" {
		t.Errorf("6-char prefix: got (%q, %v), want (Short, true)", vendor, ok)
	}
}

// ---------- Len ----------

func TestLen_NilLookup(t *testing.T) {
	var l *oui.Lookup
	if l.Len() != 0 {
		t.Errorf("nil.Len() should be 0, got %d", l.Len())
	}
}

func TestLen_NonEmpty(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "V1", "DD:EE:FF": "V2"})
	if l.Len() != 2 {
		t.Errorf("expected 2, got %d", l.Len())
	}
}

func TestLen_Empty(t *testing.T) {
	l := oui.NewLookup(map[string]string{})
	if l.Len() != 0 {
		t.Errorf("expected 0, got %d", l.Len())
	}
}

// ---------- VendorForMAC ----------

func TestVendorForMAC_Known(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok || vendor != "Cisco" {
		t.Errorf("got (%q, %v), want (Cisco, true)", vendor, ok)
	}
}

func TestVendorForMAC_Unknown(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("11:22:33:44:55:66")
	if ok {
		t.Errorf("expected no match, got %q", vendor)
	}
}

func TestVendorForMAC_NilLookup(t *testing.T) {
	var l *oui.Lookup
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if ok {
		t.Errorf("nil lookup should return false, got %q", vendor)
	}
}

func TestVendorForMAC_EmptyEntries(t *testing.T) {
	l := oui.NewLookup(map[string]string{})
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if ok {
		t.Errorf("empty lookup should return false, got %q", vendor)
	}
}

func TestVendorForMAC_InvalidMAC(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("ZZZZZZ")
	if ok {
		t.Errorf("invalid MAC should return false, got %q", vendor)
	}
}

func TestVendorForMAC_ShortMAC(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("AA:BB")
	if ok {
		t.Errorf("short MAC should return false, got %q", vendor)
	}
}

func TestVendorForMAC_CaseInsensitive(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("aa:bb:cc:dd:ee:ff")
	if !ok || vendor != "Cisco" {
		t.Errorf("lowercase: got (%q, %v)", vendor, ok)
	}
	vendor, ok = l.VendorForMAC("Aa:Bb:Cc:Dd:Ee:Ff")
	if !ok || vendor != "Cisco" {
		t.Errorf("mixed case: got (%q, %v)", vendor, ok)
	}
}

func TestVendorForMAC_DashSeparated(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("AA-BB-CC-DD-EE-FF")
	if !ok || vendor != "Cisco" {
		t.Errorf("dash: got (%q, %v)", vendor, ok)
	}
}

func TestVendorForMAC_DotSeparated(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("AA.BB.CC.DD.EE.FF")
	if !ok || vendor != "Cisco" {
		t.Errorf("dot: got (%q, %v)", vendor, ok)
	}
}

func TestVendorForMAC_WithSpaces(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("  AA:BB:CC:DD:EE:FF  ")
	if !ok || vendor != "Cisco" {
		t.Errorf("spaces: got (%q, %v)", vendor, ok)
	}
}

func TestVendorForMAC_NoSeparator(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	vendor, ok := l.VendorForMAC("AABBCCDDEEFF")
	if !ok || vendor != "Cisco" {
		t.Errorf("no-sep: got (%q, %v)", vendor, ok)
	}
}

func TestVendorForMAC_AllZeros(t *testing.T) {
	l := oui.NewLookup(map[string]string{"00:00:00": "ZeroVendor"})
	vendor, ok := l.VendorForMAC("00:00:00:00:00:00")
	if !ok || vendor != "ZeroVendor" {
		t.Errorf("zeros: got (%q, %v)", vendor, ok)
	}
}

func TestVendorForMAC_LongestPrefixWins(t *testing.T) {
	l := oui.NewLookup(map[string]string{
		"AA:BB:CC":          "Short",
		"AA:BB:CC:DD":       "Med",
		"AA:BB:CC:DD:EE:FF": "Long",
	})
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok || vendor != "Long" {
		t.Errorf("got (%q, %v), want (Long, true)", vendor, ok)
	}
}

func TestVendorForMAC_PartialMatch(t *testing.T) {
	l := oui.NewLookup(map[string]string{
		"AA:BB:CC":    "Short",
		"AA:BB:CC:DD": "Med",
	})
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok || vendor != "Med" {
		t.Errorf("got (%q, %v), want (Med, true)", vendor, ok)
	}
}

// ---------- LoadOUIFile ----------

func TestLoadOUIFile_Valid(t *testing.T) {
	l, err := oui.LoadOUIFile("../../internal/oui/oui.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l.Len() == 0 {
		t.Error("expected non-zero entries from real OUI file")
	}
	vendor, ok := l.VendorForMAC("28:6F:B9:12:34:56")
	if !ok {
		t.Error("expected to find Nokia vendor")
	}
	t.Logf("Nokia vendor: %q (total entries: %d)", vendor, l.Len())
}

func TestLoadOUIFile_NotFound(t *testing.T) {
	l, err := oui.LoadOUIFile("/nonexistent/path/oui.csv")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if l != nil {
		t.Error("expected nil lookup on error")
	}
}

func TestLoadOUIFile_EmptyFile(t *testing.T) {
	tmp := t.TempDir() + "/empty.csv"
	if err := os.WriteFile(tmp, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	l, err := oui.LoadOUIFile(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l.Len() != 0 {
		t.Errorf("expected 0 entries, got %d", l.Len())
	}
}

func TestLoadOUIFile_AllInvalidContent(t *testing.T) {
	tmp := t.TempDir() + "/bad.csv"
	content := "MA-L,ZZZZZZ,BadVendor,Addr\nMA-L,GGHHII,BadVendor2,Addr\n"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	l, err := oui.LoadOUIFile(tmp)
	if err == nil {
		t.Fatal("expected error for all-invalid content")
	}
	if l != nil {
		t.Errorf("expected nil lookup (Len==0 && err!=nil), got %v", l)
	}
}

func TestLoadOUIFile_CommentsOnly(t *testing.T) {
	tmp := t.TempDir() + "/comments.csv"
	content := "# just a comment\n; another\n"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	l, err := oui.LoadOUIFile(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l.Len() != 0 {
		t.Errorf("expected 0 entries, got %d", l.Len())
	}
}

func TestLoadOUIFile_PartialValid(t *testing.T) {
	tmp := t.TempDir() + "/partial.csv"
	content := "MA-L,ZZZZZZ,Bad,Addr\nMA-L,AA:BB:CC,Good,Addr\nMA-L,GGHHII,Bad2,Addr\n"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	l, err := oui.LoadOUIFile(tmp)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if l.Len() != 1 {
		t.Errorf("expected 1 valid entry, got %d", l.Len())
	}
	vendor, ok := l.VendorForMAC("AA:BB:CC:DD:EE:FF")
	if !ok || vendor != "Good" {
		t.Errorf("got (%q, %v), want (Good, true)", vendor, ok)
	}
}

// ---------- Concurrent access ----------

func TestVendorForMAC_Concurrent(t *testing.T) {
	l := oui.NewLookup(map[string]string{
		"AA:BB:CC": "Cisco",
		"DD:EE:FF": "Nokia",
		"11:22:33": "Samsung",
	})
	macs := []string{
		"AA:BB:CC:00:11:22",
		"DD:EE:FF:33:44:55",
		"11:22:33:66:77:88",
		"FF:FF:FF:FF:FF:FF", // unknown
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, mac := range macs {
				l.VendorForMAC(mac)
			}
		}()
	}
	wg.Wait()
}

func TestLen_Concurrent(t *testing.T) {
	l := oui.NewLookup(map[string]string{"AA:BB:CC": "Cisco"})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := l.Len()
			if n != 1 {
				t.Errorf("Len() = %d, want 1", n)
			}
		}()
	}
	wg.Wait()
}

// ---------- Real file integration ----------

func TestLoadOUIFile_RealFile_SpotCheck(t *testing.T) {
	l, err := oui.LoadOUIFile("../../internal/oui/oui.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	known := map[string]string{
		"28:6F:B9:00:00:00": "Nokia Shanghai Bell Co., Ltd.",
		"E8:0A:B9:00:00:00": "Cisco Systems, Inc",
	}
	for mac, wantVendor := range known {
		vendor, ok := l.VendorForMAC(mac)
		if !ok {
			t.Errorf("MAC %s: not found", mac)
			continue
		}
		if vendor != wantVendor {
			t.Errorf("MAC %s: got %q, want %q", mac, vendor, wantVendor)
		}
	}
}

// ---------- Reader tests ----------

// Test helpers used in scanner error test
var _ io.Reader = (*errReader)(nil)

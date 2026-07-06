package oui_test

import (
	"strings"
	"testing"

	"passivediscovery/internal/oui"
)

// Parse — covered scenarios:
//   1. Valid CSV line with MA-L prefix → entry parsed
//   2. Empty input → empty map, no error
//   3. Comment lines (#, ;, //) → skipped
//   4. Malformed hex prefix → error returned
//   5. Missing assignment (empty prefix) → error returned
//   6. Non-MA-L/MA-M/MA-S registry → skipped silently
//   7. Vendor "Private" → skipped
//   8. Vendor with excess whitespace → cleaned
//   9. Mixed-case hex normalized to uppercase
//  10. Various separator formats (colon, dash, dot)
//  11. Multiple lines → multiple entries
//  12. Header line (Registry,Assignment,...) → skipped

func TestParse_ValidMAL(t *testing.T) {
	t.Parallel()
	input := `MA-L,001A2B,Apple Inc.`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if v, ok := entries["001A2B"]; !ok || v != "Apple Inc." {
		t.Errorf("expected Apple Inc., got %q", v)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	t.Parallel()
	entries, err := oui.Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParse_CommentLines(t *testing.T) {
	t.Parallel()
	input := `# this is a comment
; another comment
// third comment
MA-L,001A2B,Test Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (comments skipped), got %d", len(entries))
	}
}

func TestParse_MalformedHex(t *testing.T) {
	t.Parallel()
	input := `MA-L,ZZZZZZ,Bad Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for malformed hex")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParse_MissingAssignment(t *testing.T) {
	t.Parallel()
	input := `MA-L,,Empty Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for empty assignment")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParse_NonMALSkipped(t *testing.T) {
	t.Parallel()
	input := `XX-L,001A2B,Test Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (non-MA-L skipped), got %d", len(entries))
	}
}

func TestParse_PrivateVendorSkipped(t *testing.T) {
	t.Parallel()
	input := `MA-L,001A2B,Private`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (Private vendor skipped), got %d", len(entries))
	}
}

func TestParse_VendorWhitespaceCleaned(t *testing.T) {
	t.Parallel()
	input := `MA-L,001A2B,  Extra   Spaces   Here  `
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v, ok := entries["001A2B"]; !ok {
		t.Fatal("expected entry to exist")
	} else if v != "Extra Spaces Here" {
		t.Errorf("expected 'Extra Spaces Here', got %q", v)
	}
}

func TestParse_MixedCaseHexNormalized(t *testing.T) {
	t.Parallel()
	input := `MA-L,00:1a:2b,Test Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := entries["001A2B"]; !ok {
		t.Error("expected uppercase normalized key 001A2B")
	}
}

func TestParse_DashSeparator(t *testing.T) {
	t.Parallel()
	input := `MA-L,00-1A-2B,Test Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := entries["001A2B"]; !ok {
		t.Error("expected dash separator to be normalized")
	}
}

func TestParse_DotSeparator(t *testing.T) {
	t.Parallel()
	input := `MA-L,00.1A.2B,Test Vendor`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := entries["001A2B"]; !ok {
		t.Error("expected dot separator to be normalized")
	}
}

func TestParse_MultipleLines(t *testing.T) {
	t.Parallel()
	input := `MA-L,001A2B,Apple Inc.
MA-L,002A3C,Google Inc.`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestParse_HeaderSkipped(t *testing.T) {
	t.Parallel()
	input := `Registry,Assignment,Organization Name
MA-L,001A2B,Apple Inc.`
	entries, err := oui.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (header skipped), got %d", len(entries))
	}
}

func TestParse_ParseErrorFormat(t *testing.T) {
	t.Parallel()
	// Multiple malformed lines
	input := `MA-L,ZZZZZZ,Bad
MA-L,YYYYYY,Also Bad`
	_, err := oui.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected parse error")
	}
	var pe *oui.ParseError
	if !strings.Contains(err.Error(), "2 malformed") {
		t.Errorf("expected multiple error count in message, got %q", err.Error())
	}
	_ = pe // type check available
}

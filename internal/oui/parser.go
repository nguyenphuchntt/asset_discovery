package oui

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

type LineError struct {
	Line int
	Text string
	Err  error
}

type ParseError struct {
	Lines []LineError
}

func (e *ParseError) Error() string {
	if e == nil || len(e.Lines) == 0 {
		return ""
	}
	first := e.Lines[0]
	if len(e.Lines) == 1 {
		return fmt.Sprintf("line %d: %v", first.Line, first.Err)
	}
	return fmt.Sprintf("%d malformed OUI rows; first at line %d: %v", len(e.Lines), first.Line, first.Err)
}

func Parse(r io.Reader) (map[string]string, error) {
	entries := make(map[string]string)
	var lineErrs []LineError

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		entry, err := parseLine(scanner.Text())
		if err != nil {
			lineErrs = append(lineErrs, LineError{
				Line: lineNo,
				Text: strings.TrimSpace(scanner.Text()),
				Err:  err,
			})
			continue
		}
		if entry.prefix == "" {
			continue
		}
		entries[entry.prefix] = entry.vendor
	}
	if err := scanner.Err(); err != nil {
		return entries, err
	}
	if len(lineErrs) > 0 {
		return entries, &ParseError{Lines: lineErrs}
	}
	return entries, nil
}

type parsedEntry struct {
	prefix   string
	vendor   string
	registry string // MA-L / MA-M / MA-S
}

func parseLine(raw string) (parsedEntry, error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
		return parsedEntry{}, nil
	}
	return parseRegistryCSVLine(line)
}

// parseRegistryCSVLine parses a single IEEE Registry CSV data row.
// The header line ("Registry,Assignment,...") is detected and skipped
// by splitRegistryRow returning (nil, nil).
func parseRegistryCSVLine(line string) (parsedEntry, error) {
	row, err := splitRegistryRow(line)
	if err != nil {
		return parsedEntry{}, err
	}
	if len(row) < 3 {
		return parsedEntry{}, nil
	}

	registry := strings.ToUpper(strings.TrimSpace(row[0]))
	if registry != "MA-L" && registry != "MA-M" && registry != "MA-S" {
		return parsedEntry{}, nil
	}

	assignment := strings.TrimSpace(row[1])
	if assignment == "" {
		return parsedEntry{}, fmt.Errorf("missing assignment for %s row", registry)
	}

	prefix, err := normalizePrefix(assignment)
	if err != nil {
		return parsedEntry{}, fmt.Errorf("invalid assignment %q: %w", assignment, err)
	}

	vendor := cleanVendor(row[2])
	if vendor == "" || strings.EqualFold(vendor, "Private") {
		return parsedEntry{}, nil
	}

	return parsedEntry{
		prefix:   prefix,
		vendor:   vendor,
		registry: registry,
	}, nil
}

// splitRegistryRow splits a CSV row using encoding/csv for correct handling
// of quoted fields containing commas. Returns (nil, nil) for lines that
// do not look like an IEEE Registry row so the caller can skip them silently.
func splitRegistryRow(line string) ([]string, error) {
	first := strings.SplitN(line, ",", 3)
	if len(first) < 3 {
		return nil, nil
	}
	head := strings.ToUpper(strings.TrimSpace(first[0]))
	if head != "REGISTRY" && head != "MA-L" && head != "MA-M" && head != "MA-S" {
		return nil, nil
	}
	r := csv.NewReader(strings.NewReader(line))
	r.FieldsPerRecord = -1
	row, err := r.Read()
	if err != nil {
		return nil, err
	}
	return row, nil
}

//	MA-L → 6 hex chars (24-bit OUI)
//	MA-M → 6 or 8 hex chars (28-bit OUI-36)
//	MA-S → 6..12 hex chars (vendor-assigned sub-block)
func prefixMatchesRegistry(prefix, registry string) bool {
	switch registry {
	case "MA-L":
		return len(prefix) == 6
	case "MA-M":
		return len(prefix) == 6 || len(prefix) == 8
	case "MA-S":
		return len(prefix) >= 6 && len(prefix) <= 12
	}
	return false
}

// convert prefix into continuously hexa chars
func normalizePrefix(input string) (string, error) {
	token := strings.TrimSpace(input)
	hex, ok := collectHex(token)
	if !ok {
		return "", fmt.Errorf("invalid hex in %q", input)
	}
	if len(hex) < 6 || len(hex) > 12 {
		return "", fmt.Errorf("prefix length %d out of range for %q (want 6..12)", len(hex), input)
	}
	return hex, nil
}

func collectHex(input string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(input) {
		switch {
		case r == ':' || r == '-' || r == '.':
			continue
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

func cleanVendor(vendor string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(vendor)), " ") // Fields for rm exceed space
}

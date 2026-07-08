package oui

import (
	"fmt"
	"os"
	"sort"
)

type Lookup struct {
	entries      map[string]string // db
	prefixLens   []int
	maxPrefixLen int // for truncate mac
}

func NewLookup(entries map[string]string) *Lookup {
	l := &Lookup{
		entries: make(map[string]string, len(entries)),
	}
	seenLens := make(map[int]struct{})
	for prefix, vendor := range entries {
		norm, err := normalizePrefix(prefix)
		if err != nil || vendor == "" {
			continue
		}
		l.entries[norm] = cleanVendor(vendor)
		seenLens[len(norm)] = struct{}{}
		if len(norm) > l.maxPrefixLen {
			l.maxPrefixLen = len(norm) // maxPrefixLen init
		}
	}
	for n := range seenLens { // key only
		l.prefixLens = append(l.prefixLens, n) // prefixLen init
	}
	sort.Sort(sort.Reverse(sort.IntSlice(l.prefixLens))) // desc
	return l
}

func LoadOUIFile(path string) (*Lookup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries, err := Parse(f)
	lookup := NewLookup(entries)
	if lookup.Len() == 0 && err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return lookup, err
}

func (l *Lookup) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

func (l *Lookup) VendorForMAC(mac string) (string, bool) {
	if l == nil || len(l.entries) == 0 {
		return "", false
	}
	norm, ok := normalizeMAC(mac)
	if !ok {
		return "", false
	}
	for _, n := range l.prefixLens {
		if vendor, ok := l.entries[norm[:n]]; ok {
			return vendor, true
		}
	}
	return "", false
}

// convert into continuous hexa format
func normalizeMAC(input string) (string, bool) {
	hex, ok := collectHex(input)
	if !ok || len(hex) != 12 {
		return "", false
	}
	return hex, true
}
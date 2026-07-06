# oui — MAC Address → Vendor Lookup

OUI (Organizationally Unique Identifier) package. Given a device MAC address, returns
the manufacturer / vendor name. Used by `internal/asset` to enrich asset snapshots.

## Data source

`oui.csv` — IEEE Registry Authority CSV export (~39,600 MA-L / MA-M / MA-S entries).

Column format:

```
Registry,Assignment,Organization Name,Organization Address
MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.","No.388 Ning Qiao Road, ..."
MA-M,28C0DD0,Some Vendor,Some Address
```

Entries with empty or `Private` Organization Name are filtered out (no useful vendor
signal).

## Flow

```
                  ┌──────────────────────┐
                  │  --oui / DISCOVERY_OUI│  (config flag / env var)
                  └──────────┬───────────┘
                             │ path
                             ▼
                     ┌───────────────┐
                     │  LoadFile()   │  opens file, calls Parse()
                     └───────┬───────┘
                             │ io.Reader
                             ▼
               ┌─────────────────────────────┐
               │  Parse(r io.Reader)         │  IEEE Registry CSV parser
               │  → map[string]string        │  prefix → vendor name
               └─────────────┬───────────────┘
                             │ map
                             ▼
               ┌─────────────────────────────┐
               │  NewLookup(entries)         │  builds sorted prefix-length index
               └─────────────┬───────────────┘
                             │ *Lookup
                             ▼
               ┌─────────────────────────────┐
               │  VendorForMAC(mac)          │  longest-prefix match
               │  → (vendor string, ok)      │
               └─────────────────────────────┘
```

### Longest-prefix strategy

MACs are normalized to 12-char uppercase hex. The lookup iterates known prefix
lengths (sorted longest-first) and returns the first match. MA-L entries are
6 chars (24-bit OUI); MA-M / MA-S may be 7–12 chars, so they win over a
shorter MA-L entry when both overlap.

## Parser details

`parseRegistryCSVLine` enforces per-registry nibble counts:

- **MA-L** — exactly 6 hex chars (24-bit OUI)
- **MA-M** — 6 or 8 hex chars (OUI-36)
- **MA-S** — 6..12 hex chars (sub-block assignment)

The header line (`Registry,Assignment,...`) is auto-detected and skipped. Comment
lines (`#`, `;`, `//`) and blank lines are ignored. Malformed rows are collected
into a `*ParseError`; partial results are still returned so the caller can warn
rather than fail.

## Usage

```go
lookup, err := oui.LoadFile("internal/oui/oui.csv")
if err != nil {
    log.Warn("OUI parse issues", "err", err)
}

vendor, ok := lookup.VendorForMAC("28:6F:B9:12:34:56")
// vendor = "Nokia Shanghai Bell Co., Ltd.", ok = true
```

CLI: `./discovery --oui internal/oui/oui.csv ...`
Env:  `DISCOVERY_OUI=internal/oui/oui.csv ./discovery ...`

## Tests

```bash
go test ./internal/oui/...
```

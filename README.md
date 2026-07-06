# Passive Asset Network Discovery System

> Passive network asset discovery — capture packets, build a real-time inventory of every device on the wire.

`passivediscovery` listens passively to a network interface (or replays a PCAP file), extracts device
fingerprints from common protocols (ARP, DHCP, mDNS, SSDP, DHCPv6), and exposes them through an
embedded web dashboard and a JSON API. No active probing, no SNMP, no agents on endpoints — purely
eavesdropping on traffic the devices already broadcast.

It is a single static Go binary, zero runtime dependencies (besides `libpcap` for live capture), with
a vanilla-JS dashboard embedded into the binary itself.

---

## Features

- **Live capture** from any NIC or **PCAP replay** for offline analysis
- **Six built-in analyzers**: Ethernet, ARP, DHCPv4, DHCPv6, mDNS, SSDP
- **Asset model**: identity (MAC / vendor / device / OS), IPv4 & IPv6 history, hostnames, services, lifecycle status, events
- **SQLite persistence** with WAL, hot/cold asset loading, batched upserts
- **Embedded dashboard** (zero-build vanilla JS SPA) with live stats, sortable/filterable asset table, asset detail drawer, event feed
- **JSON API** with cursor pagination, search, filtering, vendor list
- **Graceful shutdown**: SIGINT/SIGTERM triggers final flush + sweep + orderly teardown
- **Production deployment**: multi-stage Docker image + systemd unit with sandboxing

---

## Quick Start — Docker (live capture)

```bash
# 1. Configure
cp .env.example .env
# Edit .env to set your interface name (e.g. eth0, wlp0s20f3)

# 2. Build + run
docker compose build
docker compose up -d

# 3. Open the dashboard
xdg-open http://localhost:8080          # Linux
open http://localhost:8080              # macOS

# 4. Logs / stop
docker compose logs -f
docker compose down
```

### Configuration (`./.env`)

| Variable | Default | Description |
|---|---|---|
| `DISCOVERY_IFACE` | `eth0` | Network interface to capture from |
| `DISCOVERY_API_ADDR` | `:8080` | HTTP bind address for API + UI |
| `DISCOVERY_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `DISCOVERY_OFFLINE_AFTER` | `15m` | Asset offline threshold |
| `VERSION` | `dev` | Image tag |
| `BUILD_TIME` | empty | Build timestamp (informational) |

The container runs in `network_mode: host` with `NET_RAW` + `NET_ADMIN` capabilities, so it can sniff
on the host's NIC directly. Data is kept in two Docker named volumes:

- `discovery-output` — `/data/output` (JSON dumps, future formats)
- `discovery-db` — `/data/db` (SQLite database file `discovery.db`)

To inspect them:
```bash
docker volume inspect passivediscovery_discovery-db
docker compose exec discovery sh -c 'ls -lh /data/db'
```

> **Note:** Live capture via Docker requires Docker Engine on **Linux**. Docker Desktop on macOS/Windows
> cannot grant raw packet capture to a container. On those hosts, run the binary directly (see below)
> or use a Linux VM.

---

## Quick Start — Run from Source

```bash
# Build
CGO_ENABLED=1 go build -o bin/discovery ./cmd/discovery

# Live capture (needs cap_net_raw)
sudo setcap cap_net_raw,cap_net_admin+ep bin/discovery
./bin/discovery \
    --interface eth0 \
    --output ./output \
    --db ./output/discovery.db \
    --oui ./internal/oui/oui.csv \
    --api-addr :8080 \
    --ui

# PCAP replay (offline)
./bin/discovery \
    --pcap ./test/data/heavy/002.pcap \
    --output ./output \
    --db ./output/discovery.db \
    --oui ./internal/oui/oui.csv \
    --api-addr :8080 \
    --ui
```

---

## Installation — Systemd (bare-metal Linux)

```bash
cd deploy
sudo ./install.sh            # builds binary, creates user, installs systemd unit
sudo vi /etc/default/passivediscovery   # set DISCOVERY_INTERFACE, DISCOVERY_API_ADDR, etc.
sudo systemctl restart passivediscovery
sudo systemctl status passivediscovery
sudo journalctl -u passivediscovery -f

# Uninstall
sudo ./uninstall.sh          # keeps data
sudo ./uninstall.sh --purge  # removes binary + data + user
```

Layout after install:
- Binary: `/opt/passivediscovery/discovery`
- OUI table: `/opt/passivediscovery/oui.csv`
- Data: `/var/lib/passivediscovery/{output,db}`
- Logs: `journalctl -u passivediscovery`
- Env file: `/etc/default/passivediscovery`

The systemd unit is hardened with `ProtectSystem`, `PrivateTmp`, `ProtectHome`,
`ProtectKernelTunables`, `NoNewPrivileges`, and runs as the unprivileged `discovery` user.

## Configuration Reference

All flags accept a `DISCOVERY_*` env var equivalent. Env vars are applied first, flags override.

### Capture source (one required)
| Flag | Default | Description |
|---|---|---|
| `--pcap` | — | Replay a PCAP file |
| `--interface` | — | Live capture from interface |
| `--bpf` | empty | BPF filter expression (e.g. `arp or port 5353`) |

### Output & logging
| Flag | Default | Description |
|---|---|---|
| `--output` | `./output` | Output directory (auto-created) |
| `--oui` | — | IEEE OUI CSV for vendor lookup |
| `--log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `--log-format` | `text` | `text` or `json` |
| `--log-output` | `./output/discovery.log` | `stdout`, `stderr`, or file path |

### Processing
| Flag | Default | Description |
|---|---|---|
| `--offline-after` | `5m` | Asset offline threshold |
| `--queue-size` | `4096` | Packet queue depth |
| `--workers` | `2` | Analysis worker goroutines |
| `--flush-every` | `5s` | DB flush interval |
| `--batch-size` | `500` | DB batch size |

### Persistence
| Flag | Default | Description |
|---|---|---|
| `--db` | `./output/discovery.db` | SQLite database path (empty = no persistence) |
| `--db-wal` | `true` | Enable WAL mode |
| `--db-busy-timeout` | `5s` | SQLite busy timeout |
| `--keep-json-output` | `false` | Write JSON snapshots even when DB is enabled |
| `--load-limit` | `1000` | Max assets loaded from DB at startup (0 = unlimited) |
| `--load-window` | `24h` | Only load assets seen within this window |
| `--evict-after` | `0` (= 7× load-window) | Evict offline assets after this duration |

### API & dashboard
| Flag | Default | Description |
|---|---|---|
| `--api-addr` | empty | HTTP bind address (empty = disabled) |
| `--ui` | `false` | Serve embedded dashboard at `/` |
| `--ui-refresh-every` | `5s` | Dashboard polling interval |
| `--api-read-timeout` | `5s` | HTTP read timeout |

---

## Development

```bash
# Build
CGO_ENABLED=1 go build -o bin/discovery ./cmd/discovery

# Vet + format
go vet ./...
gofmt -l . | xargs -r gofmt -w

# Run tests
go test ./test/...

# OUI data file
ls -lh internal/oui/oui.csv
```

### Architecture notes

- **Sharded asset manager** (`internal/asset/manager.go`): 32 shards keyed by MAC, each with its
  own mutex. Allows high write concurrency.
- **Packet context** (`internal/analyzer/packetctx.go`): pre-decoded packet layers shared across
  analyzers to avoid redundant parsing.
- **Event deduplication**: events are hashed with SHA256 of
  `(asset_id, type, timestamp, source, detail, run_id)` so replays don't double-count.
- **Schema migrations** (`internal/storage/migrations.go`): embedded SQL files, version-tracked in
  `schema_migrations` table. v2 added `ON DELETE CASCADE` to all child FKs by rebuilding tables
  (SQLite limitation).
- **Hot/cold loading**: at startup only recent assets (`--load-window`, capped by `--load-limit`)
  are loaded. Cold assets hydrate on-demand.

---

## Project Layout

```
passivediscovery/
├── cmd/discovery/              # CLI entry point
├── internal/
│   ├── analyzer/               # Protocol analyzers (ARP, DHCP, mDNS, SSDP, ...)
│   ├── api/                    # HTTP API + SPA handler
│   ├── asset/                  # Asset model + sharded manager
│   ├── config/                 # Flag parsing + env var binding
│   ├── lifecycle/              # Offline/eviction tracker
│   ├── oui/                    # OUI CSV parser + lookup
│   ├── persist/                # Batched DB writer
│   ├── pipeline/               # Source → analyzer → manager
│   ├── source/                 # PCAP / live capture sources
│   └── storage/                # SQLite repo + schema migrations
├── ui/                         # Embedded dashboard (vanilla JS)
│   └── static/                 # index.html, app.js, api.js, styles.css
├── deploy/                     # systemd unit + install/uninstall scripts
├── docker-compose.yml          # Live capture mode
├── Dockerfile                  # Multi-stage build (libpcap + setcap)
├── .env.example                # Runtime config template
└── test/                       # Unit + integration tests
```

---

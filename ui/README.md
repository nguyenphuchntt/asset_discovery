# UI Dashboard Plan

Tài liệu này mô tả kế hoạch triển khai dashboard cho `passivediscovery`.
Mục tiêu là có một giao diện vận hành đọc được asset, event và runtime stats,
tự cập nhật mỗi `x` giây theo cấu hình + stats chung packet processed, throughput, total asset, v.v , nhưng không làm chậm capture pipeline.

## 1. Mục tiêu

Dashboard phải trả lời nhanh các câu hỏi vận hành:

- Hiện trong mạng có bao nhiêu asset online/offline?
- Asset mới nào vừa xuất hiện?
- IP/MAC/hostname/vendor này thuộc asset nào?
- Drop counter, queue depth, observation rate có bất thường không?
- Một asset đã thay đổi IP/hostname/vendor/status ra sao theo thời gian?

Dashboard không phải landing page. First screen là màn hình vận hành chính:
stats bar, filter/search, asset table, event timeline và detail drawer/page.

## 2. Phạm vi phiên bản đầu

### Có trong v1

- Serve static dashboard từ binary Go.
- Read-only REST API cho UI.
- Polling auto-refresh mỗi `UIRefreshEvery`.
- Manual refresh button.
- Assets table có search/filter/pagination.
- Asset detail view.
- Recent events timeline.
- Runtime stats/drop counters.
- Health/readiness display.
- Empty/loading/error/stale states rõ ràng.

### Chưa có trong v1 -> không cần 

- Auth/RBAC đầy đủ.
- Gán tag, merge/split asset bằng UI.
- WebSocket/SSE realtime.
- Topology graph.
- Alert rule editor.
- Dark/light theme setting.

Những phần này có thể làm sau khi API và persistence ổn định.

## 3. Kiến trúc đề xuất

```text
capture/analyzer/asset/persist
          |
          v
       SQLite
          |
          v
internal/api QueryRepository
          |
          +-- /api/assets
          +-- /api/assets/{id}
          +-- /api/events
          +-- /api/stats
          +-- /api/ui-config
          +-- /healthz, /readyz
          |
          v
ui/static dashboard
```

Nguyên tắc quan trọng:

- UI chỉ đọc qua API.
- API không đọc trực tiếp mutable `asset.Manager` cho list lớn.
- API read path ưu tiên đọc SQLite views hoặc snapshot cache immutable.
- List endpoint luôn pagination, không trả toàn bộ asset/event.
- Polling không được tạo request chồng nhau.

## 4. Package layout

```text
ui/
  README.md
  embed.go              # package ui, export embed.FS để internal/api serve static files
  static/
    index.html
    styles.css
    app.js
    api.js
    state.js
    format.js

internal/api/
  server.go             # http.Server lifecycle
  routes.go             # route registration
  handlers.go           # REST handlers
  models.go             # response view models
  query.go              # QueryRepository interface
  ui.go                 # static file serving + /api/ui-config
```

Lý do đặt `embed.go` trong `ui/`: Go `embed` không embed được file nằm ngoài
package directory bằng đường dẫn `..`. Package `passivediscovery/ui` sẽ export
filesystem static, còn `internal/api` import package này để serve dashboard.

## 5. Config cần thêm

Thêm vào `internal/config.Config`:

```go
type Config struct {
    APIAddr        string
    UIEnabled      bool
    UIRefreshEvery time.Duration
    APIReadTimeout time.Duration
}
```

Flags:

```text
--api-addr <addr>             Bind address cho API/UI. Empty = disabled.
--ui                          Serve dashboard static files. Default: true khi api-addr != "".
--ui-refresh-every <duration> Dashboard polling interval. Default: 5s.
--api-read-timeout <duration> Timeout cho DB/API read query. Default: 3s.
```

Env vars:

```text
DISCOVERY_API_ADDR
DISCOVERY_UI
DISCOVERY_UI_REFRESH_EVERY
DISCOVERY_API_READ_TIMEOUT
```

Validation:

- `UIRefreshEvery` phải lớn hơn 0.
- Khuyến nghị min `1s`, max `5m`.
- Nếu user truyền `500ms`, reject hoặc clamp lên `1s`.
- Nếu `--ui=true` nhưng `--api-addr` empty, trả lỗi rõ ràng.
- API bind mặc định không nên public. Khi bật mặc định nên dùng
  `127.0.0.1:8080`; nếu muốn expose container thì user đặt `:8080`.

Frontend không tự hardcode interval. Khi boot, UI gọi:

```http
GET /api/ui-config
```

Response:

```json
{
  "refresh_every_ms": 5000,
  "api_base_path": "/api",
  "features": {
    "asset_detail": true,
    "events": true,
    "stats": true,
    "sse": false
  }
}
```

## 6. Polling design

User yêu cầu dashboard update mỗi `x` giây, với `x` lấy từ config. V1 dùng
polling thay vì WebSocket/SSE để đơn giản, dễ test và không phụ thuộc runtime
stateful connection.

### Luồng boot

1. Load `GET /api/ui-config`.
2. Render shell UI ngay với loading states.
3. Fetch song song:
   - `GET /api/stats`
   - `GET /api/assets?...`
   - `GET /api/events?limit=50`
4. Set `lastUpdatedAt`.
5. Schedule refresh tiếp theo sau `refresh_every_ms`.

### Scheduler

Không dùng `setInterval` trực tiếp vì request chậm có thể chồng lên request mới.
Dùng `setTimeout` sau khi batch hiện tại kết thúc.

Pseudo-code:

```js
async function refreshLoop() {
  if (state.refreshInFlight) return scheduleNext();

  state.refreshInFlight = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), state.requestTimeoutMs);

  try {
    await refreshVisibleData(controller.signal);
    state.lastUpdatedAt = new Date();
    state.stale = false;
  } catch (err) {
    state.lastError = err;
    state.stale = true;
  } finally {
    clearTimeout(timeout);
    state.refreshInFlight = false;
    scheduleNext();
  }
}
```

### Data cần poll

Mỗi refresh poll:

- `/api/stats`
- `/api/assets` với filter/sort/page hiện tại
- `/api/events?after=<last_event_time>&limit=100` nếu API hỗ trợ incremental

Chỉ poll `/api/assets/{id}` khi detail drawer đang mở. Nếu không, tránh query
detail không cần thiết.

### Khi tab inactive

Khi `document.hidden === true`:

- pause polling hoặc tăng interval lên `max(UIRefreshEvery * 4, 30s)`;
- resume ngay khi tab visible lại;
- hiển thị `last updated`.

### Stale state

Nếu refresh lỗi liên tiếp:

- giữ dữ liệu cũ trên màn hình;
- hiển thị trạng thái `stale`;
- không clear table thành rỗng;
- backoff tối đa `60s` để tránh spam API khi DB/API lỗi.

## 7. API contract cho UI

Các response là view model ổn định, không expose schema DB thô.

### `GET /api/stats`

```json
{
  "time": "2026-07-04T10:00:00Z",
  "uptime_seconds": 3600,
  "packets_received": 1000,
  "observations": 500,
  "assets_total": 120,
  "assets_online": 95,
  "assets_offline": 25,
  "assets_created": 10,
  "assets_updated": 80,
  "kernel_dropped": 0,
  "internal_dropped": 0,
  "raw_queue_depth": 0,
  "db_flush_errors": 0
}
```

### `GET /api/assets`

Query params:

```text
q=<free text>
status=online|offline
vendor=<vendor>
source=arp|dhcpv4|mdns|ssdp|...
ip=<ip>
mac=<mac>
hostname=<hostname>
seen_after=<rfc3339>
seen_before=<rfc3339>
limit=100
cursor=<opaque cursor>
sort=last_seen_desc
```

Response:

```json
{
  "items": [
    {
      "id": "asset_001122334455",
      "status": "online",
      "mac": "00:11:22:33:44:55",
      "current_ips": ["192.168.1.10"],
      "hostnames": ["laptop-01"],
      "vendor": "Example Networks",
      "device_type": "workstation",
      "model": "",
      "os": "",
      "sources": ["arp", "dhcpv4"],
      "first_seen": "2026-07-04T09:00:00Z",
      "last_seen": "2026-07-04T10:00:00Z",
      "seen_count": 42
    }
  ],
  "page": {
    "limit": 100,
    "next_cursor": null
  }
}
```

### `GET /api/assets/{id}`

Response:

```json
{
  "asset": {
    "id": "asset_001122334455",
    "status": "online",
    "mac": "00:11:22:33:44:55",
    "vendor": "Example Networks",
    "device_type": "workstation",
    "model": "",
    "os": "",
    "os_version": "",
    "first_seen": "2026-07-04T09:00:00Z",
    "last_seen": "2026-07-04T10:00:00Z"
  },
  "ipv4_history": [
    {
      "ip": "192.168.1.10",
      "first_seen": "2026-07-04T09:00:00Z",
      "last_seen": "2026-07-04T10:00:00Z",
      "active": true
    }
  ],
  "ipv6_history": [],
  "hostnames": ["laptop-01"],
  "services": [],
  "recent_events": []
}
```

### `GET /api/events`

Query params:

```text
asset_id=<id>
type=asset_created|status_offline|status_online|...
after=<rfc3339>
before=<rfc3339>
limit=100
cursor=<opaque cursor>
```

Response:

```json
{
  "items": [
    {
      "id": "evt_...",
      "asset_id": "asset_001122334455",
      "type": "asset_created",
      "at": "2026-07-04T09:00:00Z",
      "source": "dhcpv4",
      "detail": "asset created"
    }
  ],
  "page": {
    "limit": 100,
    "next_cursor": null
  }
}
```

## 8. UI screens

### Main dashboard

Top area:

- API/DB status.
- Last updated time.
- Auto-refresh interval.
- Manual refresh icon button.
- Stale/error indicator.

Stats strip:

- total assets;
- online/offline;
- packets/sec or packets total;
- observations/sec or observations total;
- internal drops;
- kernel drops;
- queue depth;
- DB flush errors.

Filters:

- search input for MAC/IP/hostname/vendor;
- status segmented control;
- source dropdown;
- vendor dropdown;
- time range selector;
- reset filters button.

Assets table columns:

- status;
- current IP;
- MAC;
- hostname;
- vendor;
- device type;
- OS;
- sources;
- first seen;
- last seen;
- seen count.

Interaction:

- click row opens detail drawer;
- keyboard focus works on table rows;
- pagination controls use cursor;
- sort by last seen default.

### Asset detail drawer/page

Sections:

- identity: MAC, vendor, type, model, OS;
- current IPs;
- IP history;
- hostname history;
- services;
- source evidence;
- recent events timeline.

Detail view refresh:

- if open, refresh detail on the same polling cadence;
- if closed, do not fetch detail;
- if asset disappears or API returns 404, show clear message and allow close.

### Events panel

- timeline ordered newest first;
- filter by event type;
- click event opens asset detail if `asset_id` exists;
- incremental polling uses `after=last_seen_event_at` when possible.

## 9. Frontend state model

```js
const state = {
  config: {
    refreshEveryMs: 5000,
    apiBasePath: "/api"
  },
  filters: {
    q: "",
    status: "",
    vendor: "",
    source: "",
    seenAfter: "",
    seenBefore: ""
  },
  page: {
    cursor: "",
    nextCursor: null,
    limit: 100
  },
  assets: [],
  events: [],
  stats: null,
  selectedAssetId: null,
  selectedAssetDetail: null,
  refreshInFlight: false,
  lastUpdatedAt: null,
  lastError: null,
  stale: false
};
```

V1 có thể dùng vanilla JS module và DOM rendering thủ công vì scope còn nhỏ.
Nếu UI bắt đầu phức tạp hơn, chuyển sang React/Vite sau, nhưng không nên thêm
toolchain JS trước khi API contract ổn định.

## 10. Backend integration

### API server lifecycle

`cmd/discovery` hoặc future `internal/pipeline.Runner` khởi động API server khi
`cfg.APIAddr != ""`.

```go
if cfg.APIAddr != "" {
    apiServer := api.NewServer(api.Options{
        Addr:           cfg.APIAddr,
        QueryRepo:      repo,
        Stats:          statsCollector,
        UIEnabled:      cfg.UIEnabled,
        UIRefreshEvery: cfg.UIRefreshEvery,
        ReadTimeout:    cfg.APIReadTimeout,
        Logger:         logger,
    })
    group.Go(func() error { return apiServer.Run(ctx) })
}
```

Shutdown:

- `Shutdown(ctx)` với timeout riêng, ví dụ `5s`;
- không block final DB flush;
- log API startup/shutdown;
- `/readyz` trả not-ready khi DB chưa mở hoặc migration chưa xong.

### PCAP mode

PCAP mode hiện chạy xong rồi exit. Dashboard realtime chỉ có ý nghĩa nếu process
tiếp tục serve API sau khi import PCAP hoặc nếu có command riêng để mở DB.

Đề xuất:

1. Live mode: dashboard chạy trong cùng process.
2. PCAP batch mode: process import PCAP, ghi SQLite, exit như hiện tại.
3. Query/UI mode sau này:

```text
discovery serve --db ./data/passivediscovery.db --api-addr 127.0.0.1:8080
```

Mode này chỉ đọc DB và serve dashboard, không capture packet.

## 11. Performance constraints

- Polling interval nhỏ nhất `1s`.
- Mỗi list query bắt buộc có `limit`.
- Default `limit=100`, max `1000`.
- DB query timeout default `3s`.
- Frontend không request detail cho mọi asset trong table.
- Backend nên cache stats snapshot ngắn hạn nếu stats query đắt.
- API response nên gzip nếu reverse proxy hỗ trợ.

## 12. Security constraints

V1 có thể read-only, nhưng vẫn cần baseline:

- bind `127.0.0.1` mặc định;
- không bật CORS rộng mặc định;
- không expose raw payload;
- validate `limit`, cursor, time range, enum filters;
- prepared statements cho SQLite;
- log request error nhưng không leak SQL/internal stack trace ra response;
- document rằng nếu bind public thì cần reverse proxy + TLS + auth.

Auth/API key có thể thêm ở v2:

```text
DISCOVERY_API_TOKEN_FILE=/run/secrets/discovery_api_token
```

Không truyền secret bằng CLI flag.

## 13. Implementation phases

### Phase 1: API foundation

- Add config fields/flags/env for API/UI.
- Add `internal/api` package.
- Implement `/healthz`, `/readyz`, `/api/ui-config`.
- Serve embedded `ui/static`.
- Add handler tests with `httptest`.

Acceptance:

- `--api-addr 127.0.0.1:8080` starts HTTP server.
- `/api/ui-config` returns configured refresh interval.
- Static `index.html` loads.

### Phase 2: Read models

- Define `QueryRepository` for assets/events/stats.
- Implement repository against SQLite views when storage is ready.
- Temporary option: repository backed by immutable manager snapshots for dev only.
- Add pagination and filter validation.

Acceptance:

- `/api/assets` paginates and filters.
- `/api/assets/{id}` returns detail.
- `/api/events` paginates.
- `/api/stats` returns runtime counters.

### Phase 3: Dashboard shell

- Build static dashboard layout.
- Render stats strip.
- Render assets table with loading/empty/error states.
- Render filters.
- Implement manual refresh.

Acceptance:

- User sees operational dashboard as first screen.
- No marketing/landing screen.
- Text does not overflow table controls on common desktop widths.

### Phase 4: Polling and detail

- Fetch `/api/ui-config` on boot.
- Implement non-overlapping refresh loop using configured interval.
- Add stale indicator and backoff.
- Add asset detail drawer/page.
- Add recent events panel.

Acceptance:

- Changing `--ui-refresh-every 10s` changes UI polling cadence.
- Slow API requests do not overlap.
- Detail refreshes only while open.

### Phase 5: Hardening and tests

- Add Playwright smoke test:
  - dashboard loads;
  - stats visible;
  - filters update query;
  - row click opens detail;
  - manual refresh works.
- Add API error-state fixtures.
- Add responsive checks for 1366px desktop and 390px mobile.
- Add docs for Docker port exposure.

Acceptance:

- `go test ./internal/api ./internal/config` passes.
- UI smoke test passes against fake API or test server.
- Dashboard remains usable when API returns stale/error.

## 14. Future upgrades

### SSE/WebSocket

Polling is correct for v1. Khi event volume cao hoặc cần realtime hơn, thêm:

```http
GET /api/events/stream
```

Frontend dùng SSE cho event append-only, vẫn poll `/api/stats` và table theo
interval cấu hình để giữ logic đơn giản.

### Tags and operator actions

Sau khi auth/audit log có sẵn:

- add tag;
- mark asset critical;
- merge/split;
- acknowledge alert.

Mọi write action phải tạo audit event.

### Topology

Sau khi có LLDP/CDP/SNMP:

- switch/port view;
- VLAN grouping;
- asset-by-port table.

Không nên làm topology trước khi có dữ liệu topology thật.

## 15. Definition of Done

- Dashboard được serve từ binary khi API bật.
- Refresh interval lấy từ config, không hardcode trong JS.
- Polling không tạo request chồng nhau.
- Assets/events/stats hiển thị với loading/empty/error/stale states.
- List endpoints có pagination.
- API read path không block capture/write path lâu.
- `/healthz` và `/readyz` hoạt động.
- Có handler tests cho API chính.
- Có smoke test dashboard tối thiểu.

# Module `internal/capture`

> Tầng nhận packet đầu vào — gồm PCAP offline, live capture, BPF filter, fan-in
> nhiều nguồn. Cung cấp `RawPacket` cho pipeline bên dưới
> (`analyzer.Registry` → `asset.Manager`).

Tài liệu này mô tả thiết kế chi tiết (mục tiêu, kiến trúc, API, vòng đời, lỗi,
mở rộng tương lai). Phần "Triển khai hiện tại" ở cuối liệt kê file nào đang
có và file nào sẽ được tách/refactor khi áp dụng thiết kế này.

---

## 1. Mục tiêu

Module `capture` chịu trách nhiệm **một việc duy nhất**: đưa packet từ thế
giới bên ngoài (file PCAP / network interface) vào pipeline dưới dạng
`RawPacket`, sau khi áp dụng các bộ lọc ở cả kernel-level (BPF) và
application-level.

Cụ thể:

- **Đa nguồn**: file PCAP, live interface, sau này có thể thêm PCAP-NG, TZSP,
  AF_PACKET ring buffer, v.v.
- **Lọc BPF**: kernel-level filter, biểu thức kiểu `tcpdump` (`arp`,
  `port 67 and port 68`, ...), compile/validate một lần, có thể reload tại
  runtime, có thể dùng chung cho nhiều source.
- **Lọc application-level**: sau khi decode, lọc thêm theo giao thức (chỉ
  giữ ARP/DHCP), theo MAC/IP, theo cửa sổ thời gian, ... — những thứ BPF
  không diễn đạt được.
- **Backpressure**: queue bounded giữa capture goroutine và pipeline; khi
  pipeline chậm, capture phải chịu áp lực ngược thay vì nuốt trôi.
- **Stats có ý nghĩa**: phân biệt *kernel drop* (libpcap `ps.Drop`)
  và *filter drop* (BPF reject, application filter reject).
- **Shutdown sạch**: huỷ context → stop source → drain queue → close handle →
  báo cáo lỗi terminal.
- **Độc lập với pipeline bên dưới**: không biết gì về analyzer/asset, chỉ
  xuất `RawPacket` ra một channel.

---

## 2. Vị trí trong pipeline

```
                ┌────────────────────────────┐
                │       capture (tầng này)   │
                │                            │
  file.pcap ───►│  FileSource ─┐             │
                │              ├─► Pump ───► │  chan RawPacket ──► analyzer
  eth0      ───►│  LiveSource  ─┤             │                          │
                │              ├─► Pump ───► │                          ▼
  eth1      ───►│  LiveSource  ─┘             │                       asset
                │       │                    │                       Manager
                │       ▼                    │
                │   BPF (compile, reload)    │
                │   FilterChain (optional)   │
                │   Stats collector          │
                └────────────────────────────┘
```

Capture **chỉ biết** hai thứ: (1) cách mở nguồn packet; (2) cách đẩy packet ra
channel. Mọi thứ liên quan đến ý nghĩa của packet (ARP, DHCP, ...) thuộc về
analyzer.

---

## 3. Kiến trúc đề xuất

### 3.1. Phân lớp

```
┌──────────────────────────────────────────────────────────┐
│  Public API (cmd/discovery dùng)                         │
│    Manager + Options + các hàm OpenFile / OpenLive      │
├──────────────────────────────────────────────────────────┤
│  Internal                                                │
│    Source (interface) ──► FileSource, LiveSource,        │
│                           FanInSource                    │
│    BPF (compile + apply + reload)                        │
│    Filter (predicate chain, application-level)           │
│    pump (goroutine chung đọc gopacket.PacketSource       │
│          → đẩy RawPacket ra out, tôn trọng ctx)          │
│    Stats (đếm per-source + aggregated)                   │
└──────────────────────────────────────────────────────────┘
```

### 3.2. Các thành phần chính

| Thành phần | Trách nhiệm |
|---|---|
| `Source` | Một nguồn packet. `Run` bơm `RawPacket` ra channel cho tới khi EOF / lỗi / ctx cancel. |
| `FileSource` | Mở file PCAP bằng `pcap.OpenOffline`. |
| `LiveSource` | Mở interface bằng `pcap.OpenLive` với snaplen/promisc/timeout. |
| `FanInSource` | Gộp N source, merge output channel. |
| `BPF` | Compile biểu thức BPF một lần, apply/replace trên nhiều `*pcap.Handle` (thread-safe). |
| `Filter` | Predicate chạy *sau* khi packet đã decode — lọc theo layer, MAC, IP, khoảng thời gian. |
| `pump` | Helper nội bộ: `select` giữa ctx/close/packets/out. Dùng chung cho mọi Source. |
| `Stats` | Per-source và aggregated. |

---

## 4. API công khai (đề xuất)

### 4.1. `Source` interface

```go
type Source interface {
    Name() string
    Kind() SourceKind
    LinkType() layers.LinkType

    // Run bơm RawPacket vào out cho tới khi:
    //   - EOF / lỗi terminal (return non-nil error hoặc nil),
    //   - ctx bị huỷ (return ctx.Err()),
    //   - Close được gọi (return nil).
    // Khi return, Run PHẢI đóng out (defer close(out)) để pipeline biết.
    Run(ctx context.Context, out chan<- RawPacket) error

    Stats() (Stats, error)
    Close() error
}
```

**Lưu ý hợp đồng**:

- Mỗi Source chỉ được `Run` **đúng một lần**. Gọi lần hai phải trả
  `ErrSourceAlreadyRun`. Lý do: `pcap.Handle` không an toàn khi có hai goroutine
  đọc `Packets()` cùng lúc.
- `Close` phải idempotent và an toàn khi `Run` chưa từng được gọi.
- `Run` KHÔNG được block trên `out` quá lâu nếu pipeline không đọc; bounded
  channel + ctx là cơ chế backpressure. Source có thể log + đếm drop khi
  `select { out <- ... }` timeout/hủy.

### 4.2. `RawPacket`

```go
type SourceKind string

const (
    SourceKindFile SourceKind = "file"
    SourceKindLive SourceKind = "live"
    SourceKindFanIn SourceKind = "fanin" // source hợp (nhiều nguồn)
)

type SourceRef struct {
    Kind SourceKind
    Name string
}

type RawPacket struct {
    Packet gopacket.Packet
    Source SourceRef
    // CaptureInfo.Timestamp là "thời điểm bắt được" từ pcap (hoặc time.Now()
    // cho live). Pipeline dùng nó cho last-seen, offline detection.
}
```

### 4.3. Options cho từng loại source

```go
type FileOptions struct {
    Path string
    BPF  string // optional
    Name string // override Name(); default = Path
}

type LiveOptions struct {
    Interface string
    Snaplen   int32         // default 65535
    Promisc   bool          // default false
    Timeout   time.Duration // default 1s — đủ nhỏ để ctx cancel phản ứng nhanh
    BPF       string
    Name      string
}

type FanInOptions struct {
    Sources []Source // ≥ 2
    Name    string
}
```

### 4.4. `BPF`

```go
// BPF là biểu thức BPF đã được compile và có thể apply lên nhiều
// pcap.Handle. An toàn cho concurrent read; Apply/Replace cần mutex.
type BPF struct {
    expr string
    mu   sync.RWMutex
    // Không giữ handle pcap ở đây — BPF chỉ giá trị biểu thức;
    // apply lên handle là việc của Source.
}

func CompileBPF(expr string) (*BPF, error)   // expr rỗng → BPF no-op
func (b *BPF) Expr() string
func (b *BPF) Apply(h *pcap.Handle) error   // SetBPFFilter; re-entrant
```

Vì sao tách `BPF` riêng?

- Cùng một biểu thức (`arp or (port 67 and port 68)`) có thể dùng cho cả
  file và live mà không compile lại.
- Cho phép reload filter tại runtime (xem § 7) mà không phải recreate source.
- Tách phần "compile chuỗi thành chương trình BPF" khỏi phần "mở handle" —
  test được độc lập.

### 4.5. `Filter` (application-level)

```go
// Predicate chạy SAU khi packet đã decode. Trả false → packet bị loại
// (không tốn slot trong queue, không tốn CPU analyzer).
type Filter interface {
    Allow(gopacket.Packet) bool
}

// Helpers:
func AllowAll() Filter
func OnlyLayers(types ...layers.LayerType) Filter // ví dụ: ARP + DHCPv4
func DenyMAC(macs ...net.HardwareAddr) Filter
func TimeWindow(start, end time.Time) Filter
func And(filters ...Filter) Filter
func Or(filters ...Filter) Filter
func Not(f Filter) Filter
```

Lý do cần filter application-level:

- BPF có giới hạn: không lọc được theo nội dung L7 (DHCP option, hostname
  payload, ...).
- Decode trước rồi lọc rẻ hơn nhiều so với đẩy nguyên packet xuống
  analyzer registry chỉ để nó tự skip.

### 4.6. `Manager` — điểm vào chính

```go
type Manager struct { /* private */ }

type ManagerOptions struct {
    Sources []Source                 // bắt buộc, ≥ 1
    BPF     *BPF                     // optional, share cho tất cả Sources
    Filter  Filter                   // optional, mặc định AllowAll
    Queue   int                      // bounded chan size; default 4096
    Logger  *slog.Logger             // optional
}

func NewManager(opts ManagerOptions) (*Manager, error)

// Run khởi tạo channel, start mỗi Source trong goroutine riêng, đợi tất cả
// kết thúc hoặc ctx huỷ, sau đó close(out) để pipeline drain.
func (m *Manager) Run(ctx context.Context) (<-chan RawPacket, <-chan error)

// Stats trả về thống kê gộp (tổng Received/Bytes/Dropped/Filtered) + chi tiết
// per-source.
func (m *Manager) Stats() AggregateStats
```

`Manager.Run` chính là điểm gọi từ `cmd/discovery/main.go` thay vì tự quản lý
goroutine trong `main`. Lợi:

- `main.go` không phải biết về `pcap.Handle`, `gopacket.PacketSource`,
  shutdown sequence.
- `Manager` đảm bảo tất cả Source đều được `Close` kể cả khi một Source panic.
- Test được: inject mock Source, assert channel close + stats.

### 4.7. Errors

```go
var (
    ErrSourceAlreadyRun  = errors.New("capture: source already run")
    ErrOutputChannelNil  = errors.New("capture: output channel is nil")
    ErrNoSources         = errors.New("capture: manager requires at least one source")
    ErrInvalidPath       = errors.New("capture: file path is empty")
    ErrInvalidInterface  = errors.New("capture: interface is empty")
    ErrBPFCompile        = errors.New("capture: BPF expression invalid")
    ErrInterfaceNotFound = errors.New("capture: interface not found")
)
```

Mọi lỗi khác đều `fmt.Errorf("...: %w", err)` để giữ original error cho
diagnostic (`errors.Is/As`).

---

## 5. Cấu trúc file đề xuất

```
internal/capture/
├── README.md          # tài liệu này
├── capture.go         # Source interface, RawPacket, SourceRef, SourceKind
├── bpf.go             # BPF: CompileBPF, Apply, Replace
├── filter.go          # Filter interface + các helper (AllowAll, OnlyLayers, ...)
├── file.go            # FileSource + NewFileSource + FileOptions
├── live.go            # LiveSource + NewLiveSource + LiveOptions
├── fanin.go           # FanInSource + NewFanInSource + FanInOptions
├── pump.go            # func pump(ctx, packets, source, out, filter, stats) — private helper
├── stats.go           # Stats + AggregateStats + thread-safe collector
├── errors.go          # các sentinel error
└── manager.go         # Manager + NewManager + ManagerOptions + Run
```

Giữ tách file nhỏ để mỗi file một concern, dễ review, dễ test.

---

## 6. Vòng đời của một Source

```
NewXSource(opts)
    │
    │  1. Validate options (path/iface rỗng → ErrInvalidXxx)
    │  2. Mở pcap.Handle (Offline / Live)
    │  3. Nếu opts.BPF khác rỗng: handle.SetBPFFilter
    │     (compile lỗi → close handle, return ErrBPFCompile)
    │  4. Khởi tạo stats, channels
    ▼
┌─────────────┐
│ constructed │
└──────┬──────┘
       │  Run(ctx, out)
       ▼
┌──────────────────────────────────┐
│ loop:                             │
│   select {                       │
│     case <-ctx.Done(): return    │
│     case <-s.closed:   return    │
│     case pkt, ok := <-packets:   │
│       if !ok: return            │     ← PCAP EOF / handle lỗi
│       if filter != nil &&        │
│          !filter.Allow(pkt):     │     ← app-level drop
│          stats.Filtered++       │
│          continue                │
│       raw := RawPacket{...}      │
│       select {                   │
│         case <-ctx.Done(): return│
│         case <-s.closed: return │
│         case out <- raw:         │     ← backpressure: block nếu queue đầy
│           stats.Received++      │
│       }                          │
│   }                              │
└──────────────┬───────────────────┘
               │  defer Close (khi return)
               ▼
        stats final + close handle + close(s.closed)
```

Hai chỗ có thể "drop":

- **BPF drop**: đếm bởi kernel; libpcap `Stats()` trả về `ps.PacketsDropped`.
  Chỉ áp dụng cho live capture.
- **Filter drop**: đếm trong `pump` sau khi decode. Áp dụng cho cả file và live.

---

## 7. BPF: compile, apply, reload

### 7.1. Compile một lần

`BPF` chỉ lưu `expr` dạng chuỗi. Compile thực sự (parse → bytecode) xảy ra
trong `Apply(handle)` vì libpcap compile trên ngữ cảnh của datalink (Ethernet
khác với Linux SLL khác với 802.11). Tách compile + apply như thế giúp:

- `CompileBPF("arp")` chỉ validate cú pháp (nếu cần, có thể thử compile trên
  một handle tạm).
- Một `BPF` apply được cho nhiều handle, kể cả khác datalink (handle tự
  compile lại với datalink của mình).

### 7.2. Apply

```go
func (b *BPF) Apply(h *pcap.Handle) error {
    if b == nil || b.expr == "" {
        return nil
    }
    b.mu.RLock()
    defer b.mu.RUnlock()
    return h.SetBPFFilter(b.expr)
}
```

### 7.3. Reload tại runtime (mở rộng tương lai)

Một số trường hợp muốn đổi filter mà không restart process (ví dụ: từ
"capture tất cả" sang "chỉ DHCP" sau khi đã rà asset tĩnh). Thiết kế hỗ trợ:

```go
func (b *BPF) Replace(expr string, handles []*pcap.Handle) error {
    b.mu.Lock()
    old := b.expr
    b.expr = expr
    b.mu.Unlock()

    for _, h := range handles {
        if err := h.SetBPFFilter(expr); err != nil {
            // rollback nếu cần: khôi phục old cho các handle còn lại
            return err
        }
    }
    return nil
}
```

`Manager` sẽ giữ danh sách các handle đang mở để truyền vào `Replace`.

### 7.4. Sai số BPF thường gặp

| Biểu thức | Lỗi | Gợi ý |
|---|---|---|
| `port 67 68` | syntax error | `port 67 or port 68` hoặc `port 67 and port 68` |
| `host foo` | unknown host | dùng `host 192.168.1.1` |
| `vlan and arp` | không match gì | một số kernel cần `vlan and arp` không hoạt động; thử `ether proto 0x8100 and arp` |
| `greater 1500` | kernel quá cũ | nâng libpcap/kernel |

---

## 8. Filter chain (application-level)

### 8.1. Khi nào cần

- BPF reject quá nhiều packet cần thiết (vd. capture all, decode xong mới
  biết là ARP).
- Lọc theo nội dung L7 (DHCP option 12 = hostname, option 60 = vendor class).
- Loại bỏ packet từ chính máy chạy discovery (self-traffic) để tránh
  self-discovery.

### 8.2. Thứ tự áp dụng

```
libpcap kernel → BPF (kernel)
        │
        ▼
  gopacket decode
        │
        ▼
  Filter chain (application) ←─ cheap predicates (1–2 µs)
        │
        ▼
  out channel → analyzer.Registry
```

Decode là tốn nhất trong chuỗi; chỉ decode khi đã qua BPF. Filter chain phải
làm việc trên `gopacket.Packet` đã decode.

### 8.3. Ví dụ chuỗi filter mặc định cho discovery

```go
defaultFilter := And(
    OnlyLayers(layers.LayerTypeARP, layers.LayerTypeDHCPv4),
    DenyMAC(localMAC),  // self-traffic
)
```

Cài đặt hiện tại không dùng filter chain — analyzer tự skip bằng
`packet.Layer(LayerTypeARP)` trong từng analyzer. Với thiết kế mới, nên đẩy
bước skip này lên filter chain để:

- Tiết kiệm công việc của analyzer (một packet không phải ARP sẽ không gọi
  `ARPAnalyzer.Analyze`).
- Tập trung quyết định "packet nào quan trọng" ở một chỗ.

---

## 9. Stats

### 9.1. Per-source stats

```go
type Stats struct {
    SourceName string
    SourceKind SourceKind

    Received uint64 // packet đẩy thành công vào out
    Bytes    uint64 // tổng length (captureLength fallback nếu length=0)
    Dropped  uint64 // kernel drop (chỉ live)
    Filtered uint64 // filter chain reject
}
```

### 9.2. Aggregate stats

```go
type AggregateStats struct {
    Total   Stats                // sum các trường số
    PerSource map[string]Stats   // key = Source.Name()
}
```

### 9.3. Cách đếm

- `Received` tăng **ngay sau khi** `out <- raw` thành công (không tăng khi
  bị block).
- `Filtered` tăng trong pump trước khi `continue`.
- `Dropped` lấy từ `pcap.Stats()` của libpcap (chỉ có ý nghĩa cho live, file
  trả 0).
- `Bytes` cộng dồn `CaptureInfo.Length`; nếu 0 thì fallback `CaptureLength`.

### 9.4. Khi nào log / expose

- Mỗi N giây (mặc định 30s) `Manager` log stats aggregated để operator thấy
  throughput.
- Khi shutdown, log final stats kèm duration tổng.
- `cmd/discovery/main.go` đọc `Manager.Stats()` ở cuối và in vào summary.

---

## 10. Shutdown sequence

```
SIGINT/SIGTERM
   │
   ▼
ctx cancel
   │
   ▼
Mỗi Source.Run nhận ctx.Done() → return ctx.Err()
   │
   ▼
pump trong Source: defer close(handle), defer close(s.closed)
   │
   ▼
Manager.Run: đợi tất cả Source goroutine xong (WaitGroup)
   │
   ▼
close(out) → pipeline drain phần còn lại trong queue
   │
   ▼
Manager: defer Close tất cả Source (idempotent)
   │
   ▼
write outputs (assets, events) → exit
```

Yêu cầu cứng:

- `Close()` của mỗi Source phải idempotent (`sync.Once`).
- Khi `Close` được gọi giữa `Run`, pump phải thoát trong vòng `timeout` của
  libpcap (mặc định 1s cho live) — không được treo vô hạn.
- Nếu `Close` được gọi **trước** `Run`, handle phải được đóng khi Run bắt
  đầu (không double-close).

---

## 11. Multi-source / FanIn

Nhu cầu:

- Capture đồng thời nhiều interface (`eth0` cho LAN, `eth1` cho DMZ).
- Một live + một pcap replay (chạy lại sự cố trong khi tiếp tục monitor live).

`FanInSource` là một `Source` bao bọc N source con:

```go
type FanInSource struct {
    children []Source
    out      chan RawPacket
}

func NewFanInSource(children []Source, name string) (*FanInSource, error)

func (f *FanInSource) Run(ctx context.Context, out chan<- RawPacket) error {
    // Start mỗi children trong goroutine riêng, merge ra out.
    // Trả về lỗi đầu tiên (hoặc nil) khi tất cả xong.
}
```

Khi merge, giữ nguyên `RawPacket.Source` của từng child để pipeline biết
packet đến từ đâu (hữu ích cho logging, per-interface stats).

---

## 12. Đồng bộ hoá và goroutine

| Goroutine | Số lượng | Vai trò |
|---|---|---|
| `Manager.Run` | 1 | Đợi tất cả Source kết thúc |
| `Source.Run` | N (mỗi source 1) | Pump packet ra channel |
| `cmd/discovery` pipeline | 1 (mặc định) | Analyze + apply (Workers > 1: tách thành N goroutine có channel riêng) |

`Stats` collector: dùng `sync/atomic` cho hot counters (`Received`, `Bytes`,
`Filtered`); mutex cho `PerSource` map.

---

## 13. Ví dụ sử dụng (cmd/discovery)

```go
// Trong main.go sau khi parse config:
bpf, err := capture.CompileBPF(cfg.BPF)
if err != nil { return err }

var src capture.Source
switch cfg.Mode {
case config.ModePCAP:
    src, err = capture.NewFileSource(capture.FileOptions{
        Path: cfg.PCAPPath,
        BPF:  cfg.BPF, // NewFileSource sẽ tự apply lên handle
    })
case config.ModeLive:
    src, err = capture.NewLiveSource(capture.LiveOptions{
        Interface: cfg.Interface,
        Snaplen:   65535,
        Promisc:   false,
        Timeout:   time.Second,
        BPF:       cfg.BPF,
    })
}
if err != nil { return err }

mgr, err := capture.NewManager(capture.ManagerOptions{
    Sources: []capture.Source{src},
    BPF:     bpf,
    Filter:  capture.OnlyLayers(layers.LayerTypeARP, layers.LayerTypeDHCPv4),
    Queue:   cfg.QueueSize,
    Logger:  logger,
})
if err != nil { return err }

packets, errs := mgr.Run(rootCtx)

// Pipeline loop:
for raw := range packets {
    observations := registry.Analyze(raw.Packet)
    for _, obs := range observations {
        if _, err := manager.Apply(obs); err != nil {
            dropped++
        } else {
            applied++
        }
    }
}

if err := <-errs; err != nil { return err }
logger.Info("capture finished", slog.Any("stats", mgr.Stats()))
```

`main.go` hiện tại gần khớp mẫu trên, ngoại trừ chưa có `Manager` trung gian
— nó tự mở source và tự chạy goroutine. Refactor sang `Manager` giúp tách
trách nhiệm và tăng test coverage.

---

## 14. Chiến lược test

| Tầng | Loại test | Mock |
|---|---|---|
| `BPF` | unit | compile chuỗi hợp lệ / không hợp lệ |
| `Filter` | unit | packet ARP / DHCP / TCP giả, assert Allow |
| `pump` | unit | `gopacket.PacketSource` giả (chan gopacket.Packet), assert select behavior khi ctx cancel |
| `Source` (File/Live) | integration | dùng PCAP fixture nhỏ (`pcap_test.go`) |
| `Manager` | unit | inject Source giả trả packet cố định |
| `FanInSource` | unit | 2–3 source giả, assert merge đúng thứ tự |

PCAP fixture có thể là file 4–6 gói ARP/DHCP tự craft bằng `tcpdump` hoặc
script Go dùng `gopacket.PcapSink`.

---

## 15. Hướng mở rộng

| Tính năng | Cách làm |
|---|---|
| **PCAP-NG** | thêm `NewPcapNGSource` (gopacket hỗ trợ), implement `Source` |
| **AF_PACKET ring buffer** | `github.com/google/gopacket/afpacket`, thêm `AFPacketSource` — cần thiết cho high-rate (>1 Gbps) |
| **TZSP** (tunneled capture từ remote sensor) | `github.com/google/gopacket/tzsp` |
| **Multiple interface** | `FanInSource` đã handle |
| **Reload BPF khi đang chạy** | `Manager.ReloadBPF(expr string) error` — apply cho tất cả handle đang mở |
| **Self-traffic filter** | `DenyMAC(getSelfMACs()...)` trong filter chain |
| **Promiscuous per-interface** | đã có `Promisc` trong `LiveOptions` |
| **Time window** | `Filter = TimeWindow(start, end)` — hữu ích cho forensic replay |
| **PCAP write-out** (mirror ra file để debug) | wrap Source bằng `MirrorSource{inner, pcapWriter}` |

---

## 16. Triển khai hiện tại

File đang có (snapshot):

| File | Nội dung | Hành động |
|---|---|---|
| `source.go` | `Source` interface, `RawPacket`, `CaptureStats`, `SourceRef`, `SourceKind`, error sentinel | Giữ; mở rộng thêm `SourceKindFanIn`. |
| `file.go` | `FileSource` (open offline, BPF, run loop) | Refactor: dùng `BPF` + `pump` chung. |
| `live.go` | `LiveSource` (open live, BPF, run loop) | Refactor: dùng `BPF` + `pump` chung. |

File **chưa có**, cần tạo khi áp dụng thiết kế:

- `bpf.go`
- `filter.go`
- `fanin.go`
- `pump.go`
- `stats.go` (tách `CaptureStats` → `Stats` + `AggregateStats`)
- `errors.go`
- `manager.go`
- `README.md` (tài liệu này — **đã có**)

### 16.1. Vấn đề của triển khai hiện tại cần giải quyết

1. **Code trùng lặp** giữa `file.go` và `live.go` (~80% giống nhau: vòng
   `select`, `isObservable`, `packetLengths`, `recordReceived`). Sửa: rút
   thành `pump` helper.
2. **Hai kiểu shutdown không nhất quán**: `FileSource.Close` trả về ngay
   không đợi `Run`, `LiveSource.Close` đợi `runDone`. Sửa: `Manager.Close`
   thống nhất contract.
3. **BPF compile chỉ tại construction** — không reload được. Sửa: `BPF`
   riêng + `Replace`.
4. **`Dropped` chỉ có ở live** — file luôn 0, dễ gây hiểu nhầm trong stats.
   Sửa: `Stats` mới tách `Dropped` (kernel) vs `Filtered` (application).
5. **Không có application-level filter** — analyzer tự skip, lãng phí CPU.
   Sửa: thêm `Filter` chain.
6. **Không fan-in nhiều source** — chỉ một source tại một thời điểm. Sửa:
   `FanInSource` + `Manager`.
7. **`ErrOutputChanelNotFound` typo** — đổi thành `ErrOutputChannelNil`
   trong bản refactor.

### 16.2. Lộ trình refactor gợi ý

1. Viết `BPF` + unit test (compile chuỗi, apply vào handle thật).
2. Viết `Filter` + unit test (predicate trên packet giả).
3. Viết `pump` + test với `gopacket.PacketSource` giả.
4. Refactor `FileSource` dùng `BPF` + `pump`. Test PCAP fixture cũ vẫn pass.
5. Refactor `LiveSource` tương tự.
6. Viết `Manager` + `FanInSource`, refactor `cmd/discovery/main.go` dùng
   `Manager` thay vì tự quản goroutine.
7. Sau khi `Manager` ổn định, đẩy filter mặc định
   `OnlyLayers(ARP, DHCPv4)` lên config để operator có thể tắt/mở.

---

## 17. Tóm tắt quyết định thiết kế

| Quyết định | Lý do |
|---|---|
| `Source` interface trả về qua channel, không phải callback | Channel tự nhiên cho backpressure; dễ fan-in. |
| Mỗi `Source` chỉ `Run` được 1 lần | `pcap.Handle` không an toàn khi đọc song song; 1-1 tránh race. |
| `BPF` là struct riêng, không phải field trong Options | Tái sử dụng cho nhiều source, reload runtime, test độc lập. |
| `Filter` chạy sau decode, không phải trong BPF | BPF thiếu khả năng diễn đạt nội dung L7; filter chain giúp loại sớm. |
| `Manager` điều phối, `cmd/discovery` chỉ gọi một hàm | Tách trách nhiệm, tăng test coverage. |
| `Stats` thread-safe bằng atomic | Hot path không lock; chỉ mutex khi đọc aggregate. |
| `FanInSource` là một `Source` chứ không phải sửa `Manager` | Composition hơn kế thừa; có thể lồng fanin. |
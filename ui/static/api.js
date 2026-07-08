// api.js — HTTP client + mock data layer.
//
// In mock mode (default until the real backend is wired), every endpoint
// returns realistic fake data with simulated latency. When `state.useMock`
// is false and the browser can reach the real /api/ui-config, the mock
// layer is bypassed transparently.

import { state } from "./state.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MOCK_LATENCY_MIN = 40;
const MOCK_LATENCY_MAX = 120;

function mockDelay() {
  const ms = MOCK_LATENCY_MIN + Math.random() * (MOCK_LATENCY_MAX - MOCK_LATENCY_MIN);
  return new Promise(r => setTimeout(r, ms));
}

async function realFetch(path, { signal } = {}) {
  const res = await fetch(`${state.config.apiBasePath}${path}`, { signal });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const MOCK_STATS = {
  time: new Date().toISOString(),
  uptime_seconds: 1847,
  packets_received: 23814,
  assets_total: 42,
  assets_online: 31,
  assets_offline: 11,
  assets_created: 3,
  assets_updated: 18,
  kernel_dropped: 0,
  internal_dropped: 24,
  raw_queue_depth: 0,
  db_flush_errors: 1,
};

function mockNow() { return Date.now(); }
function mockMinutesAgo(m) { return new Date(mockNow() - m * 60_000).toISOString(); }
function mockHoursAgo(h) { return new Date(mockNow() - h * 3_600_000).toISOString(); }

const VENDORS = [
  "Apple, Inc.", "Samsung Electronics", "Cisco Systems", "Intel Corporation",
  "Dell Inc.", "Hewlett-Packard", "Ubiquiti Inc.", "Netgear Inc.",
  "TP-Link", "Xiaomi Communications", "Huawei Technologies",
  "D-Link Corporation", "ASUSTek Computer", "Realtek Semiconductor",
  "Juniper Networks", "Fortinet Inc.",
];

const OS_LIST = ["Windows 11", "macOS 14", "Ubuntu 22.04", "Android 14", "iOS 17", ""];
const DEV_TYPES = ["workstation", "laptop", "smartphone", "printer", "server", "camera", "router", "access-point", ""];

function rnd(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function rndIP() {
  return `192.168.1.${Math.floor(1 + Math.random() * 254)}`;
}
function rndMAC(i) {
  return `aa:${String(i).padStart(2, "0")}:bb:cc:dd:ee`.replace(/^aa:([0-9a-f]{2})/, (_, h) => {
    const base = 0x3a + i;
    return `${base.toString(16).padStart(2, "0")}:${h}`;
  });
}
function rndHostname() {
  const words = ["laptop", "desktop", "phone", "printer", "nas", "cam", "tv", "hub", "switch", "edge", "srv", "lab"];
  return `${rnd(words)}-${Math.floor(1 + Math.random() * 99)}`;
}

function generateMockAssets(count) {
  const assets = [];
  for (let i = 1; i <= count; i++) {
    const isOnline = i <= count - 11;
    const vendor = rnd(VENDORS);
    const mac = rndMAC(i);
    const ips = Array.from({ length: 1 + Math.floor(Math.random() * 2) }, () => rndIP());
    const hosts = [rndHostname()];
    const lastMinsAgo = isOnline ? Math.floor(Math.random() * 30) : 60 + Math.floor(Math.random() * 1440);
    const services = generateMockServices(isOnline);

    assets.push({
      id: `asset_${mac.replace(/:/g, "")}`,
      status: isOnline ? "online" : "offline",
      mac,
      current_ips: ips,
      hostnames: hosts,
      vendor,
      device_type: rnd(DEV_TYPES),
      model: isOnline ? "" : "",
      os: rnd(OS_LIST),
      first_seen: mockHoursAgo(3 + Math.random() * 72),
      last_seen: mockMinutesAgo(lastMinsAgo),
      seen_count: 10 + Math.floor(Math.random() * 500),
      _ipv4_history: ips.map(ip => ({
        ip,
        first_seen: mockHoursAgo(2 + Math.random() * 20),
        last_seen: mockMinutesAgo(lastMinsAgo),
        active: true,
      })),
      _hostnames_history: hosts,
      _services: services,
    });
  }
  return assets;
}

function generateMockServices(isOnline) {
  const pool = [
    { protocol: "tcp", port: 443,  name: "https",  is_client: false },
    { protocol: "tcp", port: 80,   name: "http",   is_client: false },
    { protocol: "tcp", port: 22,   name: "ssh",    is_client: false },
    { protocol: "udp", port: 5353, name: "mDNS",   is_client: false },
    { protocol: "tcp", port: 9100, name: "pdl",    is_client: false, product: rnd(["HP", "Brother", "Epson"]) },
    { protocol: "tcp", port: 443,  name: "https",  is_client: true },
    { protocol: "tcp", port: 53,   name: "dns",    is_client: true },
    { protocol: "tcp", port: 8080, name: "http",   is_client: true },
  ];
  const n = isOnline ? 1 + Math.floor(Math.random() * 3) : 0;
  return Array.from({ length: n }, () => {
    const s = rnd(pool);
    return {
      protocol: s.protocol,
      port: s.port,
      name: s.name,
      version: "",
      product: s.product || "",
      vendor: "",
      banner: "",
      is_active: true,
      is_client: s.is_client,
      last_seen: mockMinutesAgo(Math.floor(Math.random() * 10)),
    };
  });
}

let mockAssets = generateMockAssets(42);

const MOCK_UI_CONFIG = {
  refresh_every_ms: 5000,
  api_base_path: "/api",
  features: { asset_detail: true, stats: true, sse: false },
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function fetchUIConfig({ signal } = {}) {
  if (state.useMock) {
    await mockDelay();
    return structuredClone(MOCK_UI_CONFIG);
  }
  // Backend doesn't expose /ui-config yet — use sensible defaults
  // based on the standard 5s polling interval.
  return {
    refresh_every_ms: 5000,
    api_base_path: "/api",
    features: { asset_detail: true, stats: true, sse: false },
  };
}

export async function fetchStats({ signal } = {}) {
  if (state.useMock) {
    await mockDelay();
    return structuredClone(MOCK_STATS);
  }
  return realFetch("/stats", { signal });
}

export async function fetchAssets({ page, filters, signal } = {}) {
  const cursor = state.page.cursor || "";
  const limit  = state.page.limit;

  if (state.useMock) {
    await mockDelay();
    let items = [...mockAssets];

    if (filters.q) {
      const q = filters.q.toLowerCase();
      items = items.filter(a =>
        a.mac.toLowerCase().includes(q)
        || a.vendor.toLowerCase().includes(q)
        || a.hostnames.some(h => h.toLowerCase().includes(q))
        || a.current_ips.some(ip => ip.includes(q))
      );
    }
    if (filters.status) items = items.filter(a => a.status === filters.status);
    if (filters.vendor) items = items.filter(a => a.vendor === filters.vendor);

    const start = parseInt(cursor, 10) || 0;
    const pageItems = items.slice(start, start + limit);

    return {
      items: pageItems.map(a => ({
        id: a.id, status: a.status, mac: a.mac,
        current_ips: a.current_ips, hostnames: a.hostnames,
        vendor: a.vendor, device_type: a.device_type, os: a.os,
        first_seen: a.first_seen, last_seen: a.last_seen,
        seen_count: a.seen_count,
      })),
      page: {
        limit,
        next_cursor: start + limit < items.length ? String(start + limit) : null,
      },
    };
  }

  const params = new URLSearchParams();
  params.set("limit", limit);
  if (cursor) params.set("cursor", cursor);
  if (filters.q) params.set("q", filters.q);
  if (filters.status) params.set("status", filters.status);
  if (filters.vendor) params.set("vendor", filters.vendor);
  return realFetch(`/assets?${params}`, { signal });
}

export async function fetchAssetDetail(assetId, { signal } = {}) {
  if (state.useMock) {
    await mockDelay();
    const full = mockAssets.find(a => a.id === assetId);
    if (!full) throw new Error("not found");
    return {
      asset: {
        id: full.id, status: full.status, mac: full.mac, vendor: full.vendor,
        device_type: full.device_type, model: full.model,
        os: full.os, os_version: "",
        first_seen: full.first_seen, last_seen: full.last_seen,
      },
      ipv4_history: full._ipv4_history,
      ipv6_history: [],
      hostnames: full._hostnames_history,
      services: full._services,
    };
  }

  return realFetch(`/assets/${encodeURIComponent(assetId)}`, { signal });
}

export async function fetchVendors({ signal } = {}) {
  if (state.useMock) {
    await mockDelay();
    return { vendors: [...new Set(mockAssets.map(a => a.vendor).filter(Boolean))].sort() };
  }
  return realFetch("/vendors", { signal });
}

// Quick probe to see if the real API is reachable.
export async function probeRealAPI() {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    const res = await fetch("/api/stats", { signal: ctrl.signal });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

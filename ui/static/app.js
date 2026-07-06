// app.js — Dashboard controller: polling, DOM rendering, user interaction.
//
// No build step. No framework. Vanilla ES modules loaded from index.html.
// Reads from state.js, fetches via api.js, formats with format.js.

import { state, resetFilters } from "./state.js";
import {
  fetchUIConfig, fetchStats, fetchAssets,
  fetchAssetDetail, fetchEvents, fetchVendors, probeRealAPI,
} from "./api.js";
import {
  formatRelativeTime, formatClockTime,
  formatNumber, escapeHTML, debounce,
} from "./format.js";

// ---------------------------------------------------------------------------
// DOM handles
// ---------------------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {};

function cacheDOM() {
  dom.connStatus    = $("#connStatus");
  dom.lastUpdated   = $("#lastUpdated");
  dom.refreshBtn    = $("#refreshBtn");
  dom.statsBar      = $("#statsBar");
  dom.qFilter       = $("#qFilter");
  dom.statusFilter  = $("#statusFilter");
  dom.vendorFilter  = $("#vendorFilter");
  dom.sourceFilter  = $("#sourceFilter");
  dom.resetFilters  = $("#resetFilters");
  dom.assetTbody    = $("#assetTbody");
  dom.assetEmpty    = $("#assetEmpty");
  dom.assetLoading  = $("#assetLoading");
  dom.assetCount    = $("#assetCount");
  dom.prevPage      = $("#prevPage");
  dom.nextPage      = $("#nextPage");
  dom.pageInfo      = $("#pageInfo");
  dom.eventList     = $("#eventList");
  dom.eventEmpty    = $("#eventEmpty");
  dom.eventCount    = $("#eventCount");
  dom.drawer        = $("#drawer");
  dom.drawerTitle   = $("#drawerTitle");
  dom.drawerBody    = $("#drawerBody");
  dom.closeDrawer   = $("#closeDrawer");
  dom.toast         = $("#toast");
}

// ---------------------------------------------------------------------------
// Render: stats strip
// ---------------------------------------------------------------------------

function renderStats(s) {
  if (!s) return;
  const tiles = [
    { label: "assets",       value: formatNumber(s.assets_total), cls: "" },
    { label: "online",       value: formatNumber(s.assets_online), cls: "" },
    { label: "offline",      value: formatNumber(s.assets_offline), cls: s.assets_offline > 0 ? "" : "" },
    { label: "packets recv", value: formatNumber(s.packets_received), cls: "" },
    { label: "observations", value: formatNumber(s.observations), cls: "" },
    { label: "int dropped",  value: formatNumber(s.internal_dropped), cls: s.internal_dropped > 0 ? "warn" : "" },
    { label: "kernel drop",  value: formatNumber(s.kernel_dropped), cls: s.kernel_dropped > 0 ? "danger" : "" },
    { label: "db flush err", value: formatNumber(s.db_flush_errors), cls: s.db_flush_errors > 0 ? "warn" : "" },
    { label: "uptime",       value: formatUptime(s.uptime_seconds), cls: "" },
  ];
  dom.statsBar.innerHTML = tiles
    .map(t => `<div class="stat-tile ${t.cls}"><div class="value">${escapeHTML(t.value)}</div><div class="label">${escapeHTML(t.label)}</div></div>`)
    .join("");
}

function formatUptime(sec) {
  if (sec == null) return "—";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ---------------------------------------------------------------------------
// Render: assets table
// ---------------------------------------------------------------------------

function renderAssetRows(items) {
  if (!items.length) {
    dom.assetTbody.innerHTML = "";
    dom.assetEmpty.classList.remove("hidden");
    return;
  }
  dom.assetEmpty.classList.add("hidden");

  dom.assetTbody.innerHTML = items.map(a => `
    <tr data-id="${escapeHTML(a.id)}">
      <td><span class="status-dot ${escapeHTML(a.status)}"></span>${escapeHTML(a.status)}</td>
      <td class="ip-cell">${(a.current_ips || []).map(escapeHTML).join(", ")}</td>
      <td class="mac-cell">${escapeHTML(a.mac)}</td>
      <td>${(a.hostnames || []).map(escapeHTML).join(", ")}</td>
      <td>${escapeHTML(a.vendor)}</td>
      <td>${escapeHTML(a.device_type)}</td>
      <td>${escapeHTML(a.os)}</td>
      <td>${(a.sources || []).map(s => `<span class="chip">${escapeHTML(s)}</span>`).join("")}</td>
      <td title="${formatClockTime(a.last_seen)}">${formatRelativeTime(a.last_seen)}</td>
      <td>${formatNumber(a.seen_count)}</td>
    </tr>
  `).join("");
}

// ---------------------------------------------------------------------------
// Render: events list
// ---------------------------------------------------------------------------

function renderEvents(items) {
  if (!items.length) {
    dom.eventList.innerHTML = "";
    dom.eventEmpty.classList.remove("hidden");
    return;
  }
  dom.eventEmpty.classList.add("hidden");

  dom.eventList.innerHTML = items.map(e => {
    const cls = eventTypeClass(e.type);
    return `
      <li class="event-item" data-asset="${escapeHTML(e.asset_id || "")}">
        <div>
          <span class="event-type ${cls}">${escapeHTML(e.type)}</span>
          <span class="event-time">${formatRelativeTime(e.at)}</span>
        </div>
        <span class="event-detail">${escapeHTML(e.detail)}</span>
      </li>
    `;
  }).join("");
}

function eventTypeClass(type) {
  if (type.includes("created")) return "created";
  if (type.includes("offline")) return "offline";
  if (type.includes("online"))  return "online";
  if (type.includes("merged"))  return "merged";
  return "";
}

// ---------------------------------------------------------------------------
// Render: drawer detail
// ---------------------------------------------------------------------------

async function openDrawer(assetId) {
  state.selectedAssetId = assetId;
  state.selectedAssetDetail = null;
  dom.drawerTitle.textContent = assetId;
  dom.drawerBody.innerHTML = '<p class="muted">Loading…</p>';
  dom.drawer.classList.remove("hidden");
  dom.drawer.setAttribute("aria-hidden", "false");

  try {
    const detail = await fetchAssetDetail(assetId);
    state.selectedAssetDetail = detail;
    renderDrawerDetail(detail);
  } catch (err) {
    dom.drawerBody.innerHTML = `<p class="muted">Failed to load asset: ${escapeHTML(err.message)}</p>`;
  }
}

function renderDrawerDetail(d) {
  if (!d) return;
  const a = d.asset;
  dom.drawerTitle.textContent = a.id;

  dom.drawerBody.innerHTML = `
    <div class="drawer-section">
      <h4>Identity</h4>
      <dl>
        <dt>Status</dt><dd><span class="status-dot ${escapeHTML(a.status)}"></span>${escapeHTML(a.status)}</dd>
        <dt>MAC</dt><dd>${escapeHTML(a.mac)}</dd>
        <dt>Vendor</dt><dd>${escapeHTML(a.vendor)}</dd>
        <dt>Device type</dt><dd>${escapeHTML(a.device_type)}</dd>
        <dt>Model</dt><dd>${escapeHTML(a.model || "—")}</dd>
        <dt>OS</dt><dd>${escapeHTML(a.os || "—")}</dd>
        <dt>OS version</dt><dd>${escapeHTML(a.os_version || "—")}</dd>
      </dl>
    </div>

    <div class="drawer-section">
      <h4>First / Last Seen</h4>
      <dl>
        <dt>First</dt><dd>${formatClockTime(a.first_seen)}</dd>
        <dt>Last</dt><dd>${formatClockTime(a.last_seen)}</dd>
      </dl>
    </div>

    ${renderIPv4HistorySection(d.ipv4_history)}
    ${renderIPv6HistorySection(d.ipv6_history)}
    ${renderHostnamesSection(d.hostnames)}
    ${renderServicesSection(d.services)}
    ${renderRecentEventsSection(d.recent_events)}
  `;
}

function renderIPv4HistorySection(history) {
  if (!history || !history.length) return "";
  return `
    <div class="drawer-section">
      <h4>IPv4 history</h4>
      <dl>
        ${history.map(h => `
          <dt>${escapeHTML(h.ip)}</dt>
          <dd>${h.active ? "● active" : ""} ${formatRelativeTime(h.last_seen)}</dd>
        `).join("")}
      </dl>
    </div>
  `;
}

function renderIPv6HistorySection(history) {
  if (!history || !history.length) return "";
  return `
    <div class="drawer-section">
      <h4>IPv6 history</h4>
      <dl>
        ${history.map(h => `
          <dt>${escapeHTML(h.ip)}</dt>
          <dd>${h.active ? "● active" : ""} ${formatRelativeTime(h.last_seen)}</dd>
        `).join("")}
      </dl>
    </div>
  `;
}

function renderHostnamesSection(hostnames) {
  if (!hostnames || !hostnames.length) return "";
  return `
    <div class="drawer-section">
      <h4>Hostnames</h4>
      <dl>${hostnames.map(h => `<dt>${escapeHTML(h)}</dt><dd></dd>`).join("")}</dl>
    </div>
  `;
}

function renderServicesSection(services) {
  if (!services || !services.length) return "";
  const rows = services.map(s => `
    <li>
      <span class="svc-proto">${escapeHTML(s.protocol)}</span>
      <span class="svc-port">${formatNumber(s.port)}</span>
      <span>${escapeHTML(s.name)}</span>
      <span class="svc-dir">(${s.is_client ? "uses" : "serves"})</span>
      ${s.product ? `<span class="chip">${escapeHTML(s.product)}</span>` : ""}
    </li>
  `).join("");
  return `
    <div class="drawer-section">
      <h4>Services</h4>
      <ul class="service-list">${rows}</ul>
    </div>
  `;
}

function renderRecentEventsSection(events) {
  if (!events || !events.length) return "";
  return `
    <div class="drawer-section">
      <h4>Recent events</h4>
      <ul class="service-list">
        ${events.map(e => `
          <li>
            <span class="event-type ${eventTypeClass(e.type)}">${escapeHTML(e.type)}</span>
            <span>${escapeHTML(e.detail)}</span>
          </li>
        `).join("")}
      </ul>
    </div>
  `;
}

function closeDrawer() {
  state.selectedAssetId = null;
  state.selectedAssetDetail = null;
  dom.drawer.classList.add("hidden");
  dom.drawer.setAttribute("aria-hidden", "true");
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

function renderPagination() {
  const cursor = state.page.cursor;
  const nextCursor = state.page.nextCursor;
  dom.prevPage.disabled = !cursor;
  dom.nextPage.disabled = !nextCursor;
  dom.pageInfo.textContent = cursor
    ? `page (offset ${cursor})`
    : `page 1`;
}

function applyFiltersAndResetPage() {
  state.page.cursor = "";
  state.page.nextCursor = null;
  refreshData();
}

// ---------------------------------------------------------------------------
// Connection status badge
// ---------------------------------------------------------------------------

function updateConnectionBadge(connected) {
  if (connected) {
    dom.connStatus.className = "badge ok";
    dom.connStatus.textContent = state.useMock ? "mock data" : "connected";
  } else {
    dom.connStatus.className = "badge error";
    dom.connStatus.textContent = "error";
  }
}

function updateStaleBadge(stale) {
  if (stale) {
    dom.connStatus.className = "badge stale";
    dom.connStatus.textContent = "stale";
  }
}

// ---------------------------------------------------------------------------
// Toast
// ---------------------------------------------------------------------------

function showToast(msg, durationMs = 2000) {
  dom.toast.textContent = msg;
  dom.toast.classList.remove("hidden");
  setTimeout(() => dom.toast.classList.add("hidden"), durationMs);
}

// ---------------------------------------------------------------------------
// Polling loop (non-overlapping, with backoff)
// ---------------------------------------------------------------------------

let pollTimer = null;

function scheduleNext() {
  const interval = state.config.refreshEveryMs;
  const backoff = state.consecutiveErrors > 0
    ? Math.min(interval * Math.pow(2, state.consecutiveErrors), 60_000)
    : interval;
  pollTimer = setTimeout(runPoll, backoff);
}

async function runPoll() {
  if (state.refreshInFlight) return scheduleNext();
  if (document.hidden) return scheduleNext();

  state.refreshInFlight = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), state.config.refreshEveryMs);

  try {
    const [statsRes, assetsRes, eventsRes] = await Promise.all([
      fetchStats({ signal: controller.signal }),
      fetchAssets({ filters: state.filters, signal: controller.signal }),
      fetchEvents({ limit: 100, signal: controller.signal }),
    ]);

    state.stats = statsRes;
    state.assets = assetsRes.items;
    state.page.nextCursor = assetsRes.page.next_cursor;
    state.events = eventsRes.items;

    renderStats(state.stats);
    renderAssetRows(state.assets);
    dom.assetCount.textContent = formatNumber(state.assets.length);
    renderEvents(state.events);
    dom.eventCount.textContent = formatNumber(state.events.length);
    renderPagination();

    state.lastUpdatedAt = new Date();
    state.lastError = null;
    state.stale = false;
    state.consecutiveErrors = 0;

    dom.lastUpdated.textContent = `updated ${formatRelativeTime(state.lastUpdatedAt.toISOString())}`;
    dom.refreshInterval.textContent = `every ${(state.config.refreshEveryMs / 1000).toFixed(0)}s`;
    updateConnectionBadge(true);

    // If detail drawer is open, refresh it too.
    if (state.selectedAssetId && !dom.drawer.classList.contains("hidden")) {
      try {
        const detail = await fetchAssetDetail(state.selectedAssetId, { signal: controller.signal });
        state.selectedAssetDetail = detail;
        renderDrawerDetail(detail);
      } catch {
        // Keep stale data visible; don't close drawer.
      }
    }
  } catch (err) {
    state.lastError = err;
    state.consecutiveErrors++;
    if (state.stats) state.stale = true;
    updateStaleBadge(state.stale);
    if (state.consecutiveErrors >= 3) showToast("refresh failed, backing off…");
  } finally {
    clearTimeout(timeout);
    state.refreshInFlight = false;
    scheduleNext();
  }
}

async function bootPoll() {
  // Auto-detect: probe for the real API; switch off mock if reachable.
  if (state.useMock) {
    const reachable = await probeRealAPI();
    if (reachable) {
      state.useMock = false;
    }
  }

  // Load UI config first.
  try {
    state.uiConfig = await fetchUIConfig();
    state.config.refreshEveryMs = state.uiConfig.refresh_every_ms;
    state.config.features = state.uiConfig.features;
  } catch {
    // Keep defaults.
  }

  updateConnectionBadge(true);
  await runPoll();
}

// ---------------------------------------------------------------------------
// Pause on hidden tab
// ---------------------------------------------------------------------------

function handleVisibilityChange() {
  if (document.hidden) {
    clearTimeout(pollTimer);
  } else {
    state.refreshInFlight = false;
    scheduleNext();
  }
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

function bindEvents() {
  dom.refreshBtn.addEventListener("click", () => {
    clearTimeout(pollTimer);
    state.refreshInFlight = false;
    runPoll();
  });

  dom.qFilter.addEventListener("input", debounce(() => {
    state.filters.q = dom.qFilter.value;
    applyFiltersAndResetPage();
  }, 300));

  dom.statusFilter.addEventListener("change", () => {
    state.filters.status = dom.statusFilter.value;
    applyFiltersAndResetPage();
  });

  dom.vendorFilter.addEventListener("change", () => {
    state.filters.vendor = dom.vendorFilter.value;
    applyFiltersAndResetPage();
  });

  dom.sourceFilter.addEventListener("change", () => {
    state.filters.source = dom.sourceFilter.value;
    applyFiltersAndResetPage();
  });

  dom.resetFilters.addEventListener("click", () => {
    resetFilters();
    dom.qFilter.value = "";
    dom.statusFilter.value = "";
    dom.vendorFilter.value = "";
    dom.sourceFilter.value = "";
    applyFiltersAndResetPage();
  });

  dom.assetTbody.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) openDrawer(tr.dataset.id);
  });

  dom.eventList.addEventListener("click", (e) => {
    const li = e.target.closest("li[data-asset]");
    if (li && li.dataset.asset) openDrawer(li.dataset.asset);
  });

  dom.closeDrawer.addEventListener("click", closeDrawer);

  dom.drawer.addEventListener("click", (e) => {
    if (e.target === dom.drawer) closeDrawer();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !dom.drawer.classList.contains("hidden")) closeDrawer();
  });

  dom.prevPage.addEventListener("click", () => {
    // For mock: cursor is a numeric offset; go back by limit.
    const cur = parseInt(state.page.cursor, 10) || 0;
    state.page.cursor = Math.max(0, cur - state.page.limit);
    refreshData();
  });

  dom.nextPage.addEventListener("click", () => {
    if (state.page.nextCursor) {
      state.page.cursor = state.page.nextCursor;
      refreshData();
    }
  });

  document.addEventListener("visibilitychange", handleVisibilityChange);

  // Populate vendor dropdown (fetchVendors works for both mock and live)
  populateVendorFilter();
}

async function refreshData() {
  try {
    const [assetsRes, eventsRes] = await Promise.all([
      fetchAssets({ filters: state.filters }),
      fetchEvents({ limit: 100 }),
    ]);
    state.assets = assetsRes.items;
    state.page.nextCursor = assetsRes.page.next_cursor;
    state.events = eventsRes.items;

    renderAssetRows(state.assets);
    dom.assetCount.textContent = formatNumber(state.assets.length);
    renderEvents(state.events);
    dom.eventCount.textContent = formatNumber(state.events.length);
    renderPagination();
  } catch (err) {
    showToast(`refresh failed: ${err.message}`);
  }
}

async function populateVendorFilter() {
  try {
    const res = await fetchVendors();
    const vendors = res.vendors || [];
    dom.vendorFilter.innerHTML =
      '<option value="">All vendors</option>' +
      vendors.map(v => `<option value="${escapeHTML(v)}">${escapeHTML(v)}</option>`).join("");
  } catch {
    // If vendors fetch fails, just keep the current list.
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

cacheDOM();
bindEvents();
bootPoll();
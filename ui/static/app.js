// app.js — Dashboard controller: polling, DOM rendering, user interaction.
//
// No build step. No framework. Vanilla ES modules loaded from index.html.
// Reads from state.js, fetches via api.js, formats with format.js.

import { state, resetFilters } from "./state.js";
import {
  fetchUIConfig, fetchStats, fetchAssets,
  fetchAssetDetail, fetchVendors, probeRealAPI,
} from "./api.js";
import {
  formatRelativeTime, formatClockTime,
  formatNumber, escapeHTML, debounce,
} from "./format.js";

// ---------------------------------------------------------------------------
// DOM handles
// ---------------------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);

const dom = {};

function cacheDOM() {
  dom.lastUpdated   = $("#lastUpdated");
  dom.refreshBtn    = $("#refreshBtn");
  dom.statsBar      = $("#statsBar");
  dom.qFilter       = $("#qFilter");
  dom.statusFilter  = $("#statusFilter");
  dom.vendorFilter  = $("#vendorFilter");
  dom.resetFilters  = $("#resetFilters");
  dom.assetTbody    = $("#assetTbody");
  dom.assetEmpty    = $("#assetEmpty");
  dom.assetLoading  = $("#assetLoading");
  dom.prevPage      = $("#prevPage");
  dom.nextPage      = $("#nextPage");
  dom.pageInfo      = $("#pageInfo");
  dom.layout        = $("#layout");
  dom.detailPanel   = $("#detailPanel");
  dom.detailBody    = $("#detailBody");
  dom.closeDetail   = $("#closeDetail");
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

  dom.assetTbody.innerHTML = items.map(a => {
    const selected = (state.selectedAssetId === a.id) ? " selected" : "";
    return `
    <tr data-id="${escapeHTML(a.id)}" class="${selected.trim()}">
      <td class="status-cell"><span class="status-dot ${escapeHTML(a.status)}"></span>${escapeHTML(a.status || "-")}</td>
      <td class="ip-cell">${(a.current_ips || []).map(escapeHTML).join(", ")}</td>
      <td class="mac-cell">${escapeHTML(a.mac)}</td>
      <td class="hostname-cell">${(a.hostnames || []).map(escapeHTML).join(", ") || "-"}</td>
      <td class="vendor-cell">${escapeHTML(a.vendor || "-")}</td>
      <td class="device-cell">${escapeHTML(a.device_type || "-")}</td>
      <td class="os-cell">${escapeHTML(a.os || "-")}</td>
      <td title="${formatClockTime(a.last_seen)}">${formatRelativeTime(a.last_seen)}</td>
      <td>${formatNumber(a.seen_count)}</td>
    </tr>
  `;
  }).join("");
}

// ---------------------------------------------------------------------------
// Render: asset detail (sidebar)
// ---------------------------------------------------------------------------

async function openDetail(assetId) {
  state.selectedAssetId = assetId;
  state.selectedAssetDetail = null;
  dom.detailPanel.classList.remove("hidden");
  dom.layout.classList.add("has-detail");
  highlightSelectedRow();

  dom.detailBody.innerHTML = '<p class="muted detail-placeholder">Loading…</p>';

  try {
    const detail = await fetchAssetDetail(assetId);
    state.selectedAssetDetail = detail;
    renderDetail(detail);
  } catch (err) {
    dom.detailBody.innerHTML = `<p class="muted detail-placeholder">Failed to load asset: ${escapeHTML(err.message)}</p>`;
  }
}

function highlightSelectedRow() {
  const rows = dom.assetTbody.querySelectorAll("tr[data-id]");
  rows.forEach(r => r.classList.toggle("selected", r.dataset.id === state.selectedAssetId));
}

function renderDetail(d) {
  if (!d) return;
  const a = d.asset;

  dom.detailBody.innerHTML = `
    <div class="drawer-section">
      <h4>Identity</h4>
      <dl>
        <dt>Status</dt><dd><span class="status-dot ${escapeHTML(a.status)}"></span>${escapeHTML(a.status)}</dd>
        <dt>MAC</dt><dd>${escapeHTML(a.mac)}</dd>
        <dt>MAC Vendor</dt><dd>${escapeHTML(a.vendor)}</dd>
        <dt>Device</dt><dd>${escapeHTML(a.device_type)}</dd>
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
    ${renderExtrasSection(d.extras)}
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

function renderExtrasSection(extras) {
  const entries = extras ? Object.entries(extras) : [];
  if (!entries.length) return "";
  const rows = entries
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `
      <dt>${escapeHTML(k)}</dt>
      <dd><pre class="extra-value">${escapeHTML(formatExtraValue(v))}</pre></dd>
    `).join("");
  return `
    <div class="drawer-section">
      <h4>Extras</h4>
      <dl>${rows}</dl>
    </div>
  `;
}

function formatExtraValue(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  return JSON.stringify(v, null, 2);
}

function closeDetail() {
  state.selectedAssetId = null;
  state.selectedAssetDetail = null;
  dom.detailPanel.classList.add("hidden");
  dom.layout.classList.remove("has-detail");
  highlightSelectedRow();
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
    const [statsRes, assetsRes] = await Promise.all([
      fetchStats({ signal: controller.signal }),
      fetchAssets({ filters: state.filters, signal: controller.signal }),
    ]);

    state.stats = statsRes;
    state.assets = assetsRes.items;
    state.page.nextCursor = assetsRes.page.next_cursor;

    renderStats(state.stats);
    renderAssetRows(state.assets);
    highlightSelectedRow();
    renderPagination();

    state.lastUpdatedAt = new Date();
    state.lastError = null;
    state.stale = false;
    state.consecutiveErrors = 0;

    dom.lastUpdated.textContent = `updated ${formatRelativeTime(state.lastUpdatedAt.toISOString())}`;
    dom.refreshInterval.textContent = `every ${(state.config.refreshEveryMs / 1000).toFixed(0)}s`;
    if (state.selectedAssetId) {
      const stillVisible = state.assets.some(a => a.id === state.selectedAssetId);
      if (stillVisible) {
        try {
          const detail = await fetchAssetDetail(state.selectedAssetId, { signal: controller.signal });
          state.selectedAssetDetail = detail;
          renderDetail(detail);
        } catch {
          // keep stale detail visible
        }
      } else {
        // Selected asset is no longer in current page — close detail.
        closeDetail();
      }
    }
  } catch (err) {
    state.lastError = err;
    state.consecutiveErrors++;
    if (state.stats) state.stale = true;
    if (state.consecutiveErrors >= 3) showToast("refresh failed, backing off…");
  } finally {
    clearTimeout(timeout);
    state.refreshInFlight = false;
    scheduleNext();
  }
}

async function bootPoll() {
  if (state.useMock) {
    const reachable = await probeRealAPI();
    if (reachable) {
      state.useMock = false;
    }
  }

  try {
    state.uiConfig = await fetchUIConfig();
    state.config.refreshEveryMs = state.uiConfig.refresh_every_ms;
    state.config.features = state.uiConfig.features;
  } catch {
    // Keep defaults.
  }

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

  dom.resetFilters.addEventListener("click", () => {
    resetFilters();
    dom.qFilter.value = "";
    dom.statusFilter.value = "";
    dom.vendorFilter.value = "";
    applyFiltersAndResetPage();
  });

  dom.assetTbody.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    const id = tr.dataset.id;
    // Toggle: clicking same row closes detail
    if (state.selectedAssetId === id) {
      closeDetail();
    } else {
      openDetail(id);
    }
  });

  dom.closeDetail.addEventListener("click", closeDetail);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && state.selectedAssetId) closeDetail();
  });

  dom.prevPage.addEventListener("click", () => {
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

  populateVendorFilter();
}

async function refreshData() {
  try {
    const assetsRes = await fetchAssets({ filters: state.filters });
    state.assets = assetsRes.items;
    state.page.nextCursor = assetsRes.page.next_cursor;

    renderAssetRows(state.assets);
    highlightSelectedRow();
    renderPagination();

    // Drop detail if its asset isn't on this page anymore
    if (state.selectedAssetId && !state.assets.some(a => a.id === state.selectedAssetId)) {
      closeDetail();
    }
  } catch (err) {
    showToast(`refresh failed: ${err.message}`);
  }
}

async function populateVendorFilter() {
  try {
    const res = await fetchVendors();
    const vendors = res.vendors || [];
    dom.vendorFilter.innerHTML =
      '<option value="">All MAC vendors</option>' +
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

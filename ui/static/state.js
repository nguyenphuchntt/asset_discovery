// state.js — single in-memory store for the whole dashboard.
// Plain object, no framework. Modules import { state } and read/mutate directly.

export const state = {
  config: {
    refreshEveryMs: 5000,
    apiBasePath: "/api",
    features: {
      asset_detail: true,
      events: true,
      stats: true,
      sse: false,
    },
  },

  filters: {
    q: "",
    status: "",
    vendor: "",
    source: "",
  },

  page: {
    cursor: "",
    nextCursor: null,
    limit: 100,
  },

  assets: [],
  events: [],
  stats: null,
  uiConfig: null,

  selectedAssetId: null,
  selectedAssetDetail: null,

  refreshInFlight: false,
  lastUpdatedAt: null,
  lastError: null,
  stale: false,
  consecutiveErrors: 0,

  // Token bag for mock-API variants — lets app.js switch between mock and live.
  useMock: true,
};

export function resetFilters() {
  state.filters = { q: "", status: "", vendor: "", source: "" };
  state.page.cursor = "";
}
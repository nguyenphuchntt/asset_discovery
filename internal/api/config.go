package api

import "time"

// Options holds everything the API server needs to start.
type Options struct {
	Addr           string
	QueryRepo      QueryRepository
	Stats          StatsSource
	UIEnabled      bool
	UIRefreshEvery time.Duration
	ReadTimeout    time.Duration
	Logger         Logger
}

// UIConfig is the response for GET /api/ui-config.
type UIConfig struct {
	RefreshEveryMs int        `json:"refresh_every_ms"`
	APIBasePath    string     `json:"api_base_path"`
	Features       UIFeatures `json:"features"`
}

// UIFeatures are feature flags sent to the dashboard on boot.
type UIFeatures struct {
	AssetDetail bool `json:"asset_detail"`
	Events      bool `json:"events"`
	Stats       bool `json:"stats"`
	SSE         bool `json:"sse"`
}

// StatsSource provides the runtime snapshot for /api/stats.
type StatsSource interface {
	GetStats() StatsSnapshot
}

// DefaultUIConfig returns the initial UI config for the dashboard.
func DefaultUIConfig(refreshEvery time.Duration, features UIFeatures) UIConfig {
	refreshMs := int(refreshEvery / time.Millisecond)
	if refreshMs < 1000 {
		refreshMs = 5000
	}
	if !features.AssetDetail {
		features.AssetDetail = true
	}
	if !features.Events {
		features.Events = true
	}
	if !features.Stats {
		features.Stats = true
	}
	return UIConfig{
		RefreshEveryMs: refreshMs,
		APIBasePath:    "/api",
		Features:       features,
	}
}

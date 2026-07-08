package api

import "time"

type Options struct {
	Addr           string
	QueryRepo      QueryRepository
	Stats          StatsSource
	UIEnabled      bool
	UIRefreshEvery time.Duration
	ReadTimeout    time.Duration
	Logger         Logger
}

type UIConfig struct {
	RefreshEveryMs int        `json:"refresh_every_ms"`
	APIBasePath    string     `json:"api_base_path"`
	Features       UIFeatures `json:"features"`
}

type UIFeatures struct {
	AssetDetail bool `json:"asset_detail"`
	Events      bool `json:"events"`
	Stats       bool `json:"stats"`
	SSE         bool `json:"sse"`
}

type StatsSource interface {
	GetStats() StatsSnapshot
}

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

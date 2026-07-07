package api

type StatsResponse struct {
	Time            string `json:"time"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	PacketsReceived uint64 `json:"packets_received"`
	AssetsTotal     int    `json:"assets_total"`
	AssetsOnline    int    `json:"assets_online"`
	AssetsOffline   int    `json:"assets_offline"`
	AssetsCreated   uint64 `json:"assets_created"`
	AssetsUpdated   uint64 `json:"assets_updated"`
	KernelDropped   uint64 `json:"kernel_dropped"`
	InternalDropped uint64 `json:"internal_dropped"`
	RawQueueDepth   int    `json:"raw_queue_depth"`
	DBFlushErrors   uint64 `json:"db_flush_errors"`
}

type AssetListItem struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	MAC        string   `json:"mac"`
	CurrentIPs []string `json:"current_ips"`
	Hostnames  []string `json:"hostnames"`
	Vendor     string   `json:"vendor"`
	DeviceType string   `json:"device_type"`
	Model      string   `json:"model"`
	OS         string   `json:"os"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
	SeenCount  uint64   `json:"seen_count"`
}

type AssetListResponse struct {
	Items []AssetListItem `json:"items"`
	Page  PageInfo        `json:"page"`
}

type AssetIdentity struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	MAC        string `json:"mac"`
	Vendor     string `json:"vendor"`
	DeviceType string `json:"device_type"`
	Model      string `json:"model"`
	OS         string `json:"os"`
	OSVersion  string `json:"os_version"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
}

type IPHistoryEntry struct {
	IP        string `json:"ip"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Active    bool   `json:"active"`
}

type ServiceEntry struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Product  string `json:"product"`
	Vendor   string `json:"vendor"`
	Banner   string `json:"banner"`
	IsActive bool   `json:"is_active"`
	IsClient bool   `json:"is_client"`
	LastSeen string `json:"last_seen"`
}

type AssetDetailResponse struct {
	Asset       AssetIdentity    `json:"asset"`
	IPv4History []IPHistoryEntry `json:"ipv4_history"`
	IPv6History []IPHistoryEntry `json:"ipv6_history"`
	Hostnames   []string         `json:"hostnames"`
	Services    []ServiceEntry   `json:"services"`
	Extras      map[string]any   `json:"extras"`
}

type VendorsResponse struct {
	Vendors []string `json:"vendors"`
}

type PageInfo struct {
	Limit      int    `json:"limit"`
	NextCursor string `json:"next_cursor"`
}

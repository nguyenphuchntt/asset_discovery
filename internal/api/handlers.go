package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"passivediscovery/internal/asset"
)

// Logger is the minimal logger interface used by the API package.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type handler struct {
	repo      QueryRepository
	statsSrc  StatsSource
	startedAt time.Time
	uiCfg     UIConfig
	logger    Logger
}

// GET /api/stats
func (h *handler) handleStats(w http.ResponseWriter, r *http.Request) {
	uptime := int64(time.Since(h.startedAt).Seconds())
	snap := h.statsSrc.GetStats()

	resp := StatsResponse{
		Time:            time.Now().UTC().Format(time.RFC3339),
		UptimeSeconds:   uptime,
		PacketsReceived: snap.PacketsReceived,
		AssetsTotal:     snap.AssetsTotal,
		AssetsOnline:    snap.AssetsOnline,
		AssetsOffline:   snap.AssetsOffline,
		AssetsCreated:   snap.AssetsCreated,
		AssetsUpdated:   snap.AssetsUpdated,
		KernelDropped:   snap.KernelDropped,
		InternalDropped: snap.InternalDropped,
		RawQueueDepth:   snap.RawQueueDepth,
		DBFlushErrors:   snap.DBFlushErrors,
		PacketsPerSec:   snap.PacketsPerSec,
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/assets
func (h *handler) handleAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := AssetFilter{
		Q:        q.Get("q"),
		Status:   q.Get("status"),
		Vendor:   q.Get("vendor"),
		IP:       q.Get("ip"),
		MAC:      q.Get("mac"),
		Hostname: q.Get("hostname"),
		Sort:     q.Get("sort"),
	}
	if v := q.Get("limit"); v != "" {
		filter.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("seen_after"); v != "" {
		filter.SeenAfter, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("seen_before"); v != "" {
		filter.SeenBefore, _ = time.Parse(time.RFC3339, v)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.repo.ListAssets(ctx, filter)
	if err != nil {
		h.logger.Warn("ListAssets failed", slog.String("err", err.Error()))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/assets/{id}
func (h *handler) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/assets/")
	if id == "" || strings.Contains(id, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid asset id"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := h.repo.GetAssetDetail(ctx, asset.AssetID(id))
	if err != nil {
		h.logger.Warn("GetAssetDetail failed", slog.String("err", err.Error()), slog.String("id", id))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if resp == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "asset not found"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/vendors
func (h *handler) handleVendors(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	vendors, err := h.repo.ListVendors(ctx)
	if err != nil {
		h.logger.Warn("ListVendors failed", slog.String("err", err.Error()))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, VendorsResponse{Vendors: emptyIfNil(vendors)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Println("encode json:", err)
	}
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

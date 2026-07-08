package api

import (
	"io/fs"
	"net/http"
	"strings"

	"passivediscovery/ui"
)

func newMux(h *handler, uiEnabled bool) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/stats", h.handleStats)
	mux.HandleFunc("/api/assets", h.handleAssets)
	mux.HandleFunc("/api/assets/", h.handleAssetDetail)
	mux.HandleFunc("/api/vendors", h.handleVendors)

	if uiEnabled {
		mux.Handle("/", spaHandler(ui.Static))
	}
	return mux
}

func spaHandler(staticFS ui.FS) http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			http.NotFound(w, r)
			return
		}
		_, err := sub.Open(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil && r.URL.Path != "/" {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

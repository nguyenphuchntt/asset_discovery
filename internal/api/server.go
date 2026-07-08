package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type Server struct {
	http   *http.Server
	addr   string
	listen net.Listener
	logger Logger
}

// NewServer creates a new API server bound to opts.Addr.
func NewServer(opts Options) *Server {
	uiConfig := DefaultUIConfig(opts.UIRefreshEvery, UIFeatures{
		AssetDetail: true,
		Events:      true,
		Stats:       true,
		SSE:         false,
	})
	uiConfig.APIBasePath = "/api"

	h := &handler{
		repo:      opts.QueryRepo,
		statsSrc:  opts.Stats,
		startedAt: time.Now(),
		uiCfg:     uiConfig,
		logger:    opts.Logger,
	}

	timeout := opts.ReadTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	srv := &Server{
		addr:   opts.Addr,
		logger: opts.Logger,
	}
	srv.http = &http.Server{
		Addr:              opts.Addr,
		Handler:           newMux(h, opts.UIEnabled),
		ReadTimeout:       timeout,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv
}

// Run blocks until ctx is cancelled, then gracefully shuts down.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("api server starting", slog.String("addr", s.addr))
		var err error
		if s.listen != nil {
			err = s.http.Serve(s.listen)
		} else {
			err = s.http.ListenAndServe()
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("api server shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutCtx); err != nil {
			s.logger.Error("api shutdown error", slog.String("err", err.Error()))
			return err
		}
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Addr returns the bound address.
func (s *Server) Addr() string {
	return s.addr
}

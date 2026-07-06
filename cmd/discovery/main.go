package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/api"
	"passivediscovery/internal/asset"
	"passivediscovery/internal/capture"
	"passivediscovery/internal/config"
	"passivediscovery/internal/lifecycle"
	internallog "passivediscovery/internal/log"
	"passivediscovery/internal/oui"
	"passivediscovery/internal/output"
	"passivediscovery/internal/persist"
	"passivediscovery/internal/pipeline"
	"passivediscovery/internal/stats"
	"passivediscovery/internal/storage"
)

const (
	sweepInterval = time.Minute
	runIDTimeFmt  = "20060102T150405Z" // 06/07/2026 14:30:22 UTC
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Config, flags, env vars 
	cfg, err := config.Parse(args, os.Getenv)
	if errors.Is(err, config.ErrHelp) {
		fmt.Print(config.Usage())
		return nil
	}
	if err != nil {
		fmt.Fprint(os.Stderr, config.Usage())
		return err
	}
	// Logger
	logger, closer, err := internallog.NewLogger(internallog.Options{
		Level:  cfg.LogLevel,
		Format: cfg.LogFormat,
		Output: cfg.LogOutput,
	})
	if err != nil {
		fmt.Fprint(os.Stderr, config.Usage())
		return err
	}
	defer closer.Close()
	slog.SetDefault(logger)

	logger.Info("discovery starting",
		slog.String("mode", string(cfg.Mode)),
		slog.String("pcap", cfg.PCAPPath),
		slog.String("interface", cfg.Interface),
		slog.String("output", cfg.OutputDirectory),
		slog.String("oui", cfg.OUIPath),
		slog.Duration("offline_after", cfg.OfflineAfter),
	)
	// context
	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// open source
	source, err := openSource(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := source.Close(); cerr != nil {
			logger.Warn("source close failed", slog.String("err", cerr.Error()))
		}
	}()
	// manager
	mgrOpts := buildManagerOpts(cfg, logger)
	manager := asset.NewManager(nil, mgrOpts...)
	// storage
	runID := "run_" + time.Now().UTC().Format(runIDTimeFmt) // runID
	var repo storage.Repository
	if cfg.DBPath != "" {
		sqliteRepo, err := storage.OpenSQLite(storage.SQLiteOptions{
			Path:        cfg.DBPath,
			WAL:         cfg.DBWAL,
			BusyTimeout: cfg.DBBusyTimeout,
		})
		if err != nil {
			return fmt.Errorf("open sqlite: %w", err)
		}
		repo = sqliteRepo
		if err := repo.Init(rootCtx); err != nil {
			repo.Close()
			return fmt.Errorf("init storage schema: %w", err)
		}
		// Bounded startup load — only hot assets
		loadOpts := storage.LoadOptions{
			Since: time.Now().Add(-cfg.LoadWindow),
			Limit: cfg.LoadLimit,
		}
		if existing, err := repo.LoadAssets(rootCtx, loadOpts); err == nil {
			if n := manager.LoadSnapshots(existing); n > 0 {
				logger.Info("loaded persisted assets",
					slog.Int("count", n),
					slog.Int("limit", cfg.LoadLimit),
					slog.Duration("window", cfg.LoadWindow),
				)
			}
		} else {
			logger.Warn("load persisted assets failed", slog.String("err", err.Error()))
		}
		// Enable on-demand hydrate for cold/evicted assets
		manager.SetHydrator(sqliteRepo)
	}

	// Compute evictAfter: explicit flag wins, else 7× load window
	evictAfter := cfg.EvictAfter
	if evictAfter == 0 {
		evictAfter = 7 * cfg.LoadWindow
	}
	// persister
	var persister *persist.Persister
	if repo != nil {
		persister = persist.New(repo, manager, runID, logger).SetOptions(persist.Options{
			BatchSize:  cfg.BatchSize,
			FlushEvery: cfg.FlushEvery,
		})
		persisterCtx, persisterCancel := context.WithCancel(rootCtx)
		go persister.Run(persisterCtx) // flush định kỳ
		defer persisterCancel()         // cancel khi shutdown → Persister.Run tự final flush

		if err := repo.SaveRunStart(rootCtx, storage.CaptureRun{
			ID:            runID,
			Mode:          string(cfg.Mode),
			SourceName:    source.Name(),
			PCAPPath:      cfg.PCAPPath,
			InterfaceName: cfg.Interface,
			StartedAt:     time.Now().UTC(),
		}); err != nil {
			repo.Close()
			return fmt.Errorf("save run start: %w", err)
		}
		logger.Info("persistence enabled",
			slog.String("db_path", cfg.DBPath),
			slog.String("run_id", runID),
		)
	}
	// lifecycle tracker — periodic sweep (offline transitions) + eviction
	lcCtx, lcCancel := context.WithCancel(rootCtx)
	defer lcCancel()
	tracker := lifecycle.NewTracker(manager, lifecycle.RealClock{}, sweepInterval, cfg.OfflineAfter, evictAfter, logger)
	go tracker.Run(lcCtx)

	// API server — optional, enabled by --api-addr
	var apiCancel context.CancelFunc
	if cfg.APIAddr != "" {
		if sqlRepo, ok := repo.(*storage.SQLiteRepo); ok {
			queryRepo := api.NewDBQueryRepo(sqlRepo.DB())
			statsProvider := &api.InMemoryStats{
				Manager:   manager,
				Persister: persister,
			}
			apiCtx, cancel := context.WithCancel(rootCtx)
			apiCancel = cancel
			apiServer := api.NewServer(api.Options{
				Addr:           cfg.APIAddr,
				QueryRepo:      queryRepo,
				Stats:          statsProvider,
				UIEnabled:      cfg.UIEnabled,
				UIRefreshEvery: cfg.UIRefreshEvery,
				ReadTimeout:    cfg.APIReadTimeout,
				Logger:         logger,
			})
			go func() {
				if err := apiServer.Run(apiCtx); err != nil {
					logger.Error("api server error", slog.String("err", err.Error()))
				}
			}()
			logger.Info("api server started",
				slog.String("addr", cfg.APIAddr),
				slog.Bool("ui_enabled", cfg.UIEnabled),
			)
		} else {
			logger.Warn("--api-addr set but no SQLite repo available; api disabled")
		}
	}
	defer func() {
		if apiCancel != nil {
			apiCancel()
		}
	}()

	// Close the SQLite repo only after the API server has stopped —
	// the DB must stay alive while the dashboard serves queries.
	if repo != nil {
		defer func() {
			if err := repo.Close(); err != nil {
				logger.Warn("repo close failed", slog.String("err", err.Error()))
			}
		}()
	}

	// pipeline
	rawPackets := make(chan capture.RawPacket, cfg.QueueSize)
	pipe := pipeline.NewPipelineWithWorkers(analyzer.DefaultRegistry(), manager, logger, cfg.Workers)

	sourceErr := make(chan error, 1)
	go pipeline.PumpSource(rootCtx, source, rawPackets, sourceErr)

	processed, applied, dropped := pipe.Run(rootCtx, rawPackets)

	// done
	if srcErr := <-sourceErr; srcErr != nil && !errors.Is(srcErr, context.Canceled) {
		logger.Error("source terminated with error", slog.String("err", srcErr.Error()))
		return srcErr
	}

	// Stop lifecycle tracker before final flush
	lcCancel()

	// final sweep — synchronous (no eviction at shutdown; eviction only runs
	// via the lifecycle tracker to keep memory bounded during long captures)
	now := time.Now()
	sweepEvents := manager.Sweep(now, cfg.OfflineAfter)
	if n := len(sweepEvents); n > 0 {
		logger.Info("final lifecycle sweep", slog.Int("assets_marked_offline", n))
	}

	// final flush
	collector := stats.NewCollector(persister)
	runCounts := stats.RunCounts{
		RunID:           runID,
		PacketsReceived: uint64(processed),
		Observations:    uint64(applied),
		InternalDropped: uint64(dropped),
	}

	pipeline.ShutdownFlush(rootCtx, logger, repo, persister, manager, storage.CaptureRun{
		ID:               runID,
		Mode:             string(cfg.Mode),
		SourceName:       source.Name(),
		PCAPPath:         cfg.PCAPPath,
		InterfaceName:    cfg.Interface,
		StartedAt:        time.Now().UTC(),
		PacketsReceived:  uint64(processed),
		Observations:     uint64(applied),
		InternalDropped:  uint64(dropped),
	}, collector, runCounts)

	// PCAP replay finishes after the source is exhausted. Live capture stays
	// running and only shuts down on Ctrl+C. For PCAP mode we keep the API/UI
	// server alive after processing is complete so the dashboard can be
	// inspected. The user must send SIGINT/SIGTERM (Ctrl+C) to exit.
	if cfg.Mode == config.ModePCAP {
		//json output (PCAP only — live mode never writes final JSON on demand)
		if cfg.KeepJSONOutput || persister == nil {
			jsonSink := output.NewJSONSink(cfg.OutputDirectory, logger)
			snapshots := manager.Snapshot()
			events := manager.DrainEvents()

			if err := jsonSink.WriteAssets(context.Background(), snapshots); err != nil {
				logger.Error("write assets failed", slog.String("err", err.Error()))
				return err
			}
			if err := jsonSink.WriteEvents(context.Background(), events); err != nil {
				logger.Error("write events failed", slog.String("err", err.Error()))
			}
		}

		// summary
		events := manager.DrainEvents()
		output.NewStdoutSink().PrintSummary(manager.Snapshot(), events)

		logger.Info("pcap processing finished; api/ui still running, press Ctrl+C to exit",
			slog.Int("packets_processed", processed),
			slog.Int("observations_applied", applied),
			slog.Int("observations_dropped", dropped),
			slog.String("ui", cfg.APIAddr),
		)
		<-rootCtx.Done() // wait for SIGINT/SIGTERM
		logger.Info("shutdown signal received")
		return nil
	}

	// live mode: tears down immediately when source stops
	if cfg.KeepJSONOutput || persister == nil {
		jsonSink := output.NewJSONSink(cfg.OutputDirectory, logger)
		snapshots := manager.Snapshot()
		events := manager.DrainEvents()

		if err := jsonSink.WriteAssets(context.Background(), snapshots); err != nil {
			logger.Error("write assets failed", slog.String("err", err.Error()))
			return err
		}
		if err := jsonSink.WriteEvents(context.Background(), events); err != nil {
			logger.Error("write events failed", slog.String("err", err.Error()))
		}
	}

	events := manager.DrainEvents()
	output.NewStdoutSink().PrintSummary(manager.Snapshot(), events)

	logger.Info("discovery finished",
		slog.Int("packets_processed", processed),
		slog.Int("observations_applied", applied),
		slog.Int("observations_dropped", dropped),
	)
	return nil
}

func openSource(cfg *config.Config, logger *slog.Logger) (capture.Source, error) {
	switch cfg.Mode {
	case config.ModePCAP:
		logger.Info("opening PCAP source", slog.String("path", cfg.PCAPPath))
		return capture.NewFileSource(capture.FileOptions{Path: cfg.PCAPPath, BPF: cfg.BPF})
	case config.ModeLive:
		logger.Info("opening live source", slog.String("interface", cfg.Interface))
		return capture.NewLiveSource(capture.LiveOptions{Interface: cfg.Interface, BPF: cfg.BPF})
	default:
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
}

func buildManagerOpts(cfg *config.Config, logger *slog.Logger) []asset.ManagerOption {
	if cfg.OUIPath == "" {
		return nil
	}
	lookup, err := oui.LoadOUIFile(cfg.OUIPath)
	if err != nil && lookup == nil {
		logger.Error("failed to load OUI database", slog.String("err", err.Error()))
		return nil
	}
	if lookup.Len() > 0 {
		return []asset.ManagerOption{asset.WithVendorResolver(lookup)}
	}
	return nil
}
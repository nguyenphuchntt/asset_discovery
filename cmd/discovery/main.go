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
	"passivediscovery/internal/storage"
)

const sweepInterval = time.Minute

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
			logger.Warn("event",
				slog.String("event", "source_close_failed"),
				slog.String("err", cerr.Error()),
			)
		}
	}()
	// manager
	mgrOpts := buildManagerOpts(cfg, logger)
	mgrOpts = append(mgrOpts, asset.WithLogger(logger))
	manager := asset.NewManager(nil, mgrOpts...)
	// storage
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
		if err := repo.Init(rootCtx); err != nil { // init schema
			repo.Close()
			return fmt.Errorf("init storage schema: %w", err)
		}
		// reload db
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
				manager.Sweep(time.Now(), cfg.OfflineAfter)
			}
		} else {
			logger.Warn("event",
				slog.String("event", "load_assets_failed"),
				slog.String("err", err.Error()),
			)
		}
		manager.SetHydrator(sqliteRepo)
	}
	evictAfter := cfg.EvictAfter
	if evictAfter == 0 {
		evictAfter = 7 * cfg.LoadWindow
	}
	// persister + statistics baseline
	var persister *persist.Persister
	if repo != nil {
		// load last statistics row → set packets_received baseline
		if lastStat, ok, err := repo.LoadLastStatistics(rootCtx); err == nil && ok {
			manager.SetInitialCounters(lastStat.PacketsReceived)
		}

		persister = persist.New(repo, manager, logger).SetOptions(persist.Options{
			BatchSize:  cfg.BatchSize,
			FlushEvery: cfg.FlushEvery,
		}).SetStats(manager)

		persisterCtx, persisterCancel := context.WithCancel(rootCtx)
		go persister.Run(persisterCtx)
		defer persisterCancel()

		logger.Info("persistence enabled",
			slog.String("db_path", cfg.DBPath),
		)
	}
	// lifecycle tracker
	lcCtx, lcCancel := context.WithCancel(rootCtx)
	defer lcCancel()
	tracker := lifecycle.NewTracker(manager, lifecycle.RealClock{}, sweepInterval, cfg.OfflineAfter, evictAfter, logger)
	go tracker.Run(lcCtx)

	// packet rate ring-buffer rotator (rolls the rolling 60s window every 1s)
	prCtx, prCancel := context.WithCancel(rootCtx)
	defer prCancel()
	go manager.PacketRate().Run(prCtx)

	// API server
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
					logger.Error("event",
						slog.String("event", "api_error"),
						slog.String("err", err.Error()),
					)
				}
			}()
			logger.Info("api server started",
				slog.String("addr", cfg.APIAddr),
				slog.Bool("ui_enabled", cfg.UIEnabled),
			)
		} else {
			logger.Warn("event",
				slog.String("event", "api_disabled_no_db"),
				slog.String("msg", "--api-addr set but no SQLite repo available; api disabled"),
			)
		}
	}
	defer func() {
		if apiCancel != nil {
			apiCancel()
		}
	}()

	// Close the SQLite repo only after the API server has stopped
	if repo != nil {
		defer func() {
			if err := repo.Close(); err != nil {
				logger.Warn("event",
					slog.String("event", "repo_close_failed"),
					slog.String("err", err.Error()),
				)
			}
		}()
	}

	// pipeline
	rawPackets := make(chan capture.RawPacket, cfg.QueueSize)
	pipe := pipeline.NewPipelineWithWorkers(analyzer.DefaultRegistry(), manager, logger, cfg.Workers)

	sourceErr := make(chan error, 1)
	go pipeline.PumpSource(rootCtx, source, rawPackets, sourceErr)

	// marker: pipeline started — before any packet is processed
	logger.Info("pipeline_started",
		slog.Int("workers", cfg.Workers),
		slog.Int("queue_size", cfg.QueueSize),
		slog.String("source_name", source.Name()),
		slog.String("source_kind", string(source.Kind())),
	)
	pipelineStart := time.Now()

	processed, applied, dropped := pipe.Run(rootCtx, rawPackets)
	pipelineElapsedMS := time.Since(pipelineStart).Milliseconds()

	// packets_read from capture source — read AFTER Run() so counters are final
	var packetsRead uint64
	if srcStats, err := source.Stats(); err == nil {
		packetsRead = srcStats.Received
	}

	// marker: pipeline done — parseable by scripts/run_single_test.sh
	logger.Info("pipeline_done",
		slog.Uint64("packets_read", packetsRead),
		slog.Int("packets_processed", processed),
		slog.Int("observations_applied", applied),
		slog.Int("internal_dropped", dropped),
		slog.Int64("elapsed_ms", pipelineElapsedMS),
	)

	// done
	if srcErr := <-sourceErr; srcErr != nil && !errors.Is(srcErr, context.Canceled) {
		logger.Error("event",
			slog.String("event", "source_error"),
			slog.String("err", srcErr.Error()),
		)
		return srcErr
	}

	lcCancel()

	// final sweep
	now := time.Now()
	if n := manager.Sweep(now, cfg.OfflineAfter); n > 0 {
		logger.Info("final lifecycle sweep", slog.Int("assets_marked_offline", n))
	}

	// final flush
	pipeline.ShutdownFlush(rootCtx, logger, repo, persister, manager)

	if cfg.Mode == config.ModePCAP {
		if cfg.KeepJSONOutput || persister == nil {
			jsonSink := output.NewJSONSink(cfg.OutputDirectory, logger)
			snapshots := manager.Snapshot()

			if err := jsonSink.WriteAssets(context.Background(), snapshots); err != nil {
				logger.Error("event",
					slog.String("event", "json_write_failed"),
					slog.String("err", err.Error()),
				)
				return err
			}
		}

		// summary
		output.NewStdoutSink().PrintSummary(manager.Snapshot())

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

		if err := jsonSink.WriteAssets(context.Background(), snapshots); err != nil {
			logger.Error("event",
				slog.String("event", "json_write_failed"),
				slog.String("err", err.Error()),
			)
			return err
		}
	}

	output.NewStdoutSink().PrintSummary(manager.Snapshot())

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
		logger.Info("opening live source",
			slog.String("interface", cfg.Interface),
			slog.Bool("promisc", cfg.Promisc),
		)
		return capture.NewLiveSource(capture.LiveOptions{Interface: cfg.Interface, BPF: cfg.BPF, Promisc: cfg.Promisc})
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
		logger.Error("event",
			slog.String("event", "oui_load_failed"),
			slog.String("err", err.Error()),
		)
		return nil
	}
	if lookup.Len() > 0 {
		return []asset.ManagerOption{asset.WithVendorResolver(lookup)}
	}
	return nil
}
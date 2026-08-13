package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/api"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/eventbus"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/logging"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func main() {
	logger := logging.New(os.Getenv("LOG_LEVEL"))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}
	logger = logging.New(cfg.LogLevel)
	for _, msg := range config.AuthPostureWarnings(cfg) {
		logger.Warn(msg)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("connect database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	st := store.New(pool, cfg.ExpiringSoonDays)
	st.SetConnectionsKey(cfg.ConnectionsKey)
	sc := scanner.New(scanner.Config{
		Timeout:            cfg.ScanTimeout,
		AllowPrivateRanges: cfg.AllowPrivateRanges,
	})

	srv := api.NewServer(cfg, st, sc, logger)
	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      srv.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Event dispatcher (ADR 0001, Phase 1b): reactive delivery of outbox events to
	// Ansible EDA. No-op unless EDA_WEBHOOK_URL is set.
	dispCtx, dispCancel := context.WithCancel(context.Background())
	defer dispCancel()
	var dispWG sync.WaitGroup
	dispatcher := eventbus.New(eventbus.Config{
		WebhookURL:  cfg.EDAWebhookURL,
		Token:       cfg.EDAWebhookToken,
		Interval:    cfg.EventDispatchInterval,
		BatchSize:   cfg.EventDispatchBatch,
		MaxAttempts: cfg.EventMaxAttempts,
	}, st, logger)
	if dispatcher.Configured() {
		logger.Info("starting event dispatcher", "interval", cfg.EventDispatchInterval)
		dispWG.Add(1)
		go func() {
			defer dispWG.Done()
			dispatcher.Run(dispCtx)
		}()
	}

	go func() {
		logger.Info("starting server", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	dispCancel() // stop the event dispatcher before draining HTTP
	dispWG.Wait()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shiguanglab/access-gateway/internal/authz"
	"github.com/shiguanglab/access-gateway/internal/config"
	"github.com/shiguanglab/access-gateway/internal/gateway"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	authorizer, err := authz.NewClient(cfg.AuthServiceURL, cfg.AuthServiceToken, cfg.AuthTimeout)
	if err != nil {
		logger.Error("create auth client", "error", err)
		os.Exit(1)
	}
	handler, err := gateway.NewHandler(cfg, authorizer, logger)
	if err != nil {
		logger.Error("create gateway handler", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		logger.Info("access gateway listening", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	stop, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	<-stop.Done()

	ctx, shutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdown()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

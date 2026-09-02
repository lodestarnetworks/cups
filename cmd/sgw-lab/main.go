package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lodestarnetworks/cups/internal/api"
	"github.com/lodestarnetworks/cups/internal/lab"
	"github.com/lodestarnetworks/cups/internal/telemetry"
)

var version = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	tick := flag.Duration("tick", 2*time.Second, "simulated telemetry update interval")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *tick < 100*time.Millisecond {
		fmt.Fprintln(os.Stderr, "tick must be at least 100ms")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	now := time.Now().UTC()
	store := telemetry.NewStore(lab.InitialSnapshot(now))
	generator := lab.NewGenerator(store, now)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go generator.Run(ctx, *tick)

	handler := api.NewHandler(store, api.Config{AllowedOrigins: []string{
		"http://localhost:3000",
		"http://127.0.0.1:3000",
	}})
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("SGW-C/SGW-U lab telemetry API started", "listen", *listen, "mode", "simulated-lab")
		serveErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case err := <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

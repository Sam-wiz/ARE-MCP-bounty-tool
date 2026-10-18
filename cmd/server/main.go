// Package main starts either the original stdio MCP server or the local cloud
// workflow gateway. HTTP mode requires both databases and authentication.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/core"
	"github.com/samrudh/hack-ai-v2/internal/mcp"
	"github.com/samrudh/hack-ai-v2/internal/storage"
	"github.com/samrudh/hack-ai-v2/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

var Version = "2.1.0-dev"
var Revision = "working-tree"

const Name = "hack-ai-v2"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config.LoadDotEnv()
	mode := os.Getenv("SERVER_TRANSPORT")
	if mode == "" {
		mode = "stdio"
	}
	if mode != "stdio" && mode != "http" {
		return errors.New("SERVER_TRANSPORT must be stdio or http")
	}
	if mode == "http" && len(os.Getenv("API_TOKEN")) < 32 {
		return errors.New("HTTP mode requires API_TOKEN with at least 32 characters")
	}
	cfg := config.LoadOrDefault(getConfigPath())
	if v := os.Getenv("MONGODB_URI"); v != "" {
		cfg.MongoDB.URI = v
	}
	if v := os.Getenv("MONGODB_DATABASE"); v != "" {
		cfg.MongoDB.Database = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("REDIS_DB"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return errors.New("invalid REDIS_DB")
		}
		cfg.Redis.DB = n
	}
	if v := os.Getenv("WORKSPACE_DIR"); v != "" {
		cfg.Workspace.BaseDir = v
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	shutdownTracing, err := telemetry.Setup(ctx, Version)
	if err != nil {
		return fmt.Errorf("initialize tracing: %w", err)
	}
	defer func() {
		closeCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = shutdownTracing(closeCtx)
	}()
	mongoClient, err := storage.NewMongoClient(ctx, cfg.MongoDB.URI, cfg.MongoDB.Database)
	if err != nil {
		if mode == "http" {
			return errors.New("MongoDB unavailable; check credentials and connectivity")
		}
		logger.Warn("MongoDB unavailable; stdio persistence disabled")
	} else {
		defer func() {
			closeCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = mongoClient.Close(closeCtx)
		}()
	}
	redisClient, err := core.NewRedisClientWithOptions(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		if mode == "http" {
			return errors.New("Redis unavailable; check credentials and connectivity")
		}
		logger.Warn("Redis unavailable; stdio queue disabled")
	} else {
		defer redisClient.Close()
	}
	engine := core.NewEngine(core.EngineConfig{MongoDB: mongoClient, Redis: redisClient, Config: cfg})
	server := mcp.NewServer(mcp.ServerConfig{Name: Name, Version: Version, Engine: engine})
	logger.Info("server starting", "transport", mode, "version", Version, "revision", Revision)
	if mode == "stdio" {
		// Close the OS pipe on signal so a blocked ReadBytes can return.
		go func() { <-ctx.Done(); _ = os.Stdin.Close() }()
		err = server.ServeStdio(ctx, os.Stdin, os.Stdout)
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	handler, err := server.HTTPHandler(mcp.HTTPConfig{Token: os.Getenv("API_TOKEN"), Version: Version, Revision: Revision, Logger: logger, Ready: func(ctx context.Context) error {
		for _, dep := range []struct {
			name string
			ping func(context.Context) error
		}{{"mongodb", mongoClient.Ping}, {"redis", redisClient.Ping}} {
			depCtx, span := otel.Tracer("are-mcp/dependencies").Start(ctx, dep.name+" ping")
			err := dep.ping(depCtx)
			if err != nil {
				span.SetStatus(codes.Error, "dependency unavailable")
			}
			span.End()
			if err != nil {
				return errors.New("dependency unavailable")
			}
		}
		return nil
	}})
	if err != nil {
		return err
	}
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	httpServer := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	errs := make(chan error, 1)
	go func() { errs <- httpServer.ListenAndServe() }()
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			_ = httpServer.Close()
			return err
		}
	}
	return nil
}
func getConfigPath() string {
	if p := os.Getenv("HACK_AI_CONFIG"); p != "" {
		return p
	}
	return "config/config.yaml"
}

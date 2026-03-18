// Package main is the entry point for the hack-ai-v2 MCP server
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/core"
	"github.com/samrudh/hack-ai-v2/internal/mcp"
	"github.com/samrudh/hack-ai-v2/internal/storage"
)

const (
	Version = "2.0.0"
	Name    = "hack-ai-v2"
)

func main() {
	// Setup logging to stderr (stdout is for MCP communication)
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Print banner
	printBanner()

	// Load configuration
	cfg := config.LoadOrDefault(getConfigPath())
	log.Printf("Config loaded (MongoDB: %s, Redis: %s)", cfg.MongoDB.URI, cfg.Redis.Addr)

	// Allow env vars to override config file values
	if envMongo := os.Getenv("MONGODB_URI"); envMongo != "" {
		cfg.MongoDB.URI = envMongo
	}
	if envRedis := os.Getenv("REDIS_ADDR"); envRedis != "" {
		cfg.Redis.Addr = envRedis
	}

	// Initialize context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		cancel()
	}()

	// Initialize MongoDB connection
	mongoClient, err := storage.NewMongoClient(ctx, cfg.MongoDB.URI)
	if err != nil {
		log.Printf("Warning: MongoDB not available: %v", err)
		log.Println("Continuing without decision logging...")
		mongoClient = nil
	} else {
		defer mongoClient.Close(ctx)
		log.Println("MongoDB connected successfully")
	}

	// Initialize Redis connection
	redisClient, err := core.NewRedisClient(cfg.Redis.Addr)
	if err != nil {
		log.Printf("Warning: Redis not available: %v", err)
		log.Println("Continuing without async task queue...")
		redisClient = nil
	} else {
		defer redisClient.Close()
		log.Println("Redis connected successfully")
	}

	// Initialize core engine
	engine := core.NewEngine(core.EngineConfig{
		MongoDB: mongoClient,
		Redis:   redisClient,
		Config:  cfg,
	})

	// Initialize MCP server
	server := mcp.NewServer(mcp.ServerConfig{
		Name:    Name,
		Version: Version,
		Engine:  engine,
	})

	// Run MCP server over stdio
	log.Println("Starting MCP server on stdio...")
	if err := server.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server shutdown complete")
}

func printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║   Bug Bounty Automation v2.0 - Go Edition                    ║
║   Validation Pipeline | OPSEC Layer | 154 Tools              ║
║   Decision Logging | Autonomous Workers                      ║
╚══════════════════════════════════════════════════════════════╝
`
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintln(os.Stderr, "Server Status: STARTING")
	fmt.Fprintln(os.Stderr, "Protocol: MCP (Model Context Protocol)")
	fmt.Fprintln(os.Stderr, "Transport: stdio")
	fmt.Fprintln(os.Stderr, "")
}

func getConfigPath() string {
	if path := os.Getenv("HACK_AI_CONFIG"); path != "" {
		return path
	}
	return "config/config.yaml"
}

// Package core contains the core engine and execution logic
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/storage"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// EngineConfig holds engine configuration
type EngineConfig struct {
	MongoDB *storage.MongoClient
	Redis   *RedisClient
	Config  *config.Config
}

// Engine is the core execution engine
type Engine struct {
	config   EngineConfig
	session  *types.Session
	program  string // active bounty program slug
	findings map[string]*types.Finding
	workers  map[string]*Worker
	plugins  *PluginRegistry
	mu       sync.RWMutex
}

// Worker represents an autonomous worker
type Worker struct {
	ID        string
	Type      string
	Target    string
	Status    types.TaskStatus
	Progress  int
	StartedAt time.Time
	Cancel    context.CancelFunc
}

// NewEngine creates a new core engine
func NewEngine(config EngineConfig) *Engine {
	e := &Engine{
		config:   config,
		findings: make(map[string]*types.Finding),
		workers:  make(map[string]*Worker),
		plugins:  NewPluginRegistry(),
	}

	// Load plugins
	if err := e.plugins.LoadPlugins("plugins"); err != nil {
		log.Printf("Warning: Failed to load some plugins: %v", err)
	}

	return e
}

// ExecuteTool executes a tool and returns the result
func (e *Engine) ExecuteTool(ctx context.Context, name string, args map[string]interface{}) (types.ToolResult, error) {
	log.Printf("Executing tool: %s", name)

	// Log decision to MongoDB if available
	if e.config.MongoDB != nil {
		e.logDecision(ctx, name, args)
	}

	switch name {
	// Scope & Configuration
	case "set_target":
		return e.handleSetTarget(ctx, args)
	case "validate_scope":
		return e.handleValidateScope(ctx, args)

	// Bounty Program Management
	case "set_program":
		return e.handleSetProgram(ctx, args)
	case "list_programs":
		return e.handleListPrograms(ctx, args)
	case "program_stats":
		return e.handleProgramStats(ctx, args)

	// Reconnaissance
	case "recon_discover":
		return e.handleReconDiscover(ctx, args)

	// Scanning
	case "scan_vulnerabilities":
		return e.handleScanVulnerabilities(ctx, args)

	// Injection Testing
	case "test_injection":
		return e.handleTestInjection(ctx, args)

	// Cloud Testing
	case "test_cloud":
		return e.handleTestCloud(ctx, args)

	// Mobile Testing
	case "test_mobile":
		return e.handleTestMobile(ctx, args)
	case "download_app":
		return e.handleDownloadApp(ctx, args)

	// Fuzzing
	case "fuzz_target":
		return e.handleFuzzTarget(ctx, args)

	// Validation
	case "validate_finding":
		return e.handleValidateFinding(ctx, args)

	// Evidence
	case "capture_evidence":
		return e.handleCaptureEvidence(ctx, args)

	// OPSEC
	case "opsec_setup":
		return e.handleOpsecSetup(ctx, args)
	case "opsec_verify":
		return e.handleOpsecVerify(ctx, args)

	// Consultation
	case "consult_human":
		return e.handleConsultHuman(ctx, args)

	// Decision Logging
	case "log_decision":
		return e.handleLogDecision(ctx, args)

	// State & Reporting
	case "get_findings":
		return e.handleGetFindings(ctx, args)
	case "generate_report":
		return e.handleGenerateReport(ctx, args)

	// Workers
	case "list_workers":
		return e.handleListWorkers(ctx, args)
	case "stop_worker":
		return e.handleStopWorker(ctx, args)

	// New tools — Phase 1
	case "ingest_result":
		return e.handleIngestResult(ctx, args)
	case "run_tool":
		return e.handleRunTool(ctx, args)
	case "api_test":
		return e.handleAPITest(ctx, args)
	case "http_request":
		return e.handleHTTPRequest(ctx, args)

	// New tools — Phase 2
	case "compare_responses":
		return e.CompareResponses(ctx, args)

	// New tools — Phase 3
	case "discover_config":
		return e.handleDiscoverConfig(ctx, args)
	case "test_websocket":
		return e.handleTestWebSocket(ctx, args)

	// Sandbox execution
	case "execute_hunting_script":
		return e.handleExecuteHuntingScript(ctx, args)
	case "log_vector_status":
		return e.handleLogVectorStatus(ctx, args)

	default:
		// Try plugin
		if plugin, exists := e.plugins.Get(name); exists {
			return e.executePlugin(ctx, plugin, args)
		}
		return types.ToolResult{
			Content: []types.ContentBlock{{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", name)}},
			IsError: true,
		}, nil
	}
}

// ReadResource reads a resource
func (e *Engine) ReadResource(uri string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	switch uri {
	case "findings://all":
		findings := make([]*types.Finding, 0, len(e.findings))
		for _, f := range e.findings {
			findings = append(findings, f)
		}
		data, _ := json.MarshalIndent(findings, "", "  ")
		return string(data), nil

	case "session://current":
		if e.session == nil {
			return "{}", nil
		}
		data, _ := json.MarshalIndent(e.session, "", "  ")
		return string(data), nil

	case "decisions://recent":
		if e.config.MongoDB != nil {
			decisions, _ := e.config.MongoDB.GetRecentDecisions(context.Background(), 20)
			data, _ := json.MarshalIndent(decisions, "", "  ")
			return string(data), nil
		}
		return "[]", nil

	default:
		return "", fmt.Errorf("unknown resource: %s", uri)
	}
}

// GetProgram returns the active bounty program slug
func (e *Engine) GetProgram() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.program
}

// logDecision logs a tool execution decision to MongoDB
func (e *Engine) logDecision(ctx context.Context, toolName string, args map[string]interface{}) {
	argsJSON, _ := json.Marshal(args)

	decision := &types.DecisionLog{
		Program:   e.GetProgram(),
		Timestamp: time.Now(),
		SessionID: e.getSessionID(),
		Target:    e.getTarget(),
		Action:    "tool_call",
		ToolUsed:  toolName,
		ToolArgs:  string(argsJSON),
	}

	if err := e.config.MongoDB.LogDecision(ctx, decision); err != nil {
		log.Printf("Failed to log decision: %v", err)
	}
}

func (e *Engine) getSessionID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.session != nil {
		return e.session.ID
	}
	return ""
}

func (e *Engine) getTarget() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.session != nil {
		return e.session.Target
	}
	return ""
}

// Helper to create success result
func successResult(text string) types.ToolResult {
	return types.ToolResult{
		Content: []types.ContentBlock{{Type: "text", Text: text}},
	}
}

// Helper to create error result
func errorResult(text string) types.ToolResult {
	return types.ToolResult{
		Content: []types.ContentBlock{{Type: "text", Text: text}},
		IsError: true,
	}
}

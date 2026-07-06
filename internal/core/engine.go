// Package core contains the core engine and execution logic
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/director"
	"github.com/samrudh/hack-ai-v2/internal/reviewer"
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
	reviewer       *reviewer.Reviewer
	director       *director.Director
	scope          types.Scope // authoritative active scope (set by set_program AND set_target)
	egressProxyURL string      // runtime egress proxy (set via opsec_setup); overrides env/config
	mu             sync.RWMutex
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
		reviewer: reviewer.New(),
		director: director.New(),
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

	// Wireless attack chain
	case "wifi_attack":
		return e.handleWifiAttack(ctx, args)

	// Sandbox execution
	case "execute_hunting_script":
		return e.handleExecuteHuntingScript(ctx, args)
	case "log_vector_status":
		return e.handleLogVectorStatus(ctx, args)

	// v2 review pipeline
	case "precheck_finding":
		return e.handlePrecheckFinding(ctx, args)
	case "review_report":
		return e.handleReviewReport(ctx, args)
	case "request_horizon":
		return e.handleRequestHorizon(ctx, args)
	case "log_triage_outcome":
		return e.handleLogTriageOutcome(ctx, args)
	case "mark_submit_ready":
		return e.handleMarkSubmitReady(ctx, args)
	case "record_lesson":
		return e.handleRecordLesson(ctx, args)
	case "review_stats":
		return e.handleReviewStats(ctx, args)

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

// setActiveScope records the authoritative scope for enforcement.
func (e *Engine) setActiveScope(s types.Scope) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scope = s
}

// activeScope returns the scope to enforce against: the engine-level scope
// (set by set_program or set_target) with the session scope as a fallback.
func (e *Engine) activeScope() types.Scope {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.scope.InScope) > 0 || len(e.scope.OutOfScope) > 0 {
		return e.scope
	}
	if e.session != nil {
		return e.session.Scope
	}
	return types.Scope{}
}

// validateArgsScope enforces scope on any URL/host-bearing argument a tool
// receives. Used by the request tools so scope is not enforced on http_request
// alone.
func (e *Engine) validateArgsScope(args map[string]interface{}) error {
	for _, k := range []string{"url", "url1", "url2", "target", "domain", "host", "endpoint"} {
		if v, ok := args[k].(string); ok && v != "" {
			if err := e.validateURLScope(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// logDecision logs a tool execution decision to MongoDB. When the caller
// includes optional "reasoning"/"thinking"/"context" arguments alongside the
// tool's real arguments, they are captured into the decision so the WHY of each
// action is recorded (the engine cannot otherwise see the model's rationale —
// MCP only delivers {name, arguments}).
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
		Reasoning: metaArg(args, "reasoning", "why"),
		Thinking:  metaArg(args, "thinking"),
		Context:   metaArg(args, "context"),
	}

	if err := e.config.MongoDB.LogDecision(ctx, decision); err != nil {
		log.Printf("Failed to log decision: %v", err)
	}
}

// metaArg returns the first non-empty string value among the given keys.
func metaArg(args map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := args[k].(string); ok {
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	return ""
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

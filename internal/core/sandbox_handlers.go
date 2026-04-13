package core

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
	"github.com/samrudh/hack-ai-v2/internal/workspace"
)

// ============================================================================
// SANDBOX HANDLERS — execute_hunting_script & log_vector_status
// ============================================================================

// handleExecuteHuntingScript validates args and delegates to ExecuteHuntingScript
func (e *Engine) handleExecuteHuntingScript(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	// Validate required args
	code, _ := args["code"].(string)
	if code == "" {
		return errorResult("❌ 'code' is required — pass the script source code"), nil
	}

	runtime, _ := args["runtime"].(string)
	if runtime != "python" && runtime != "bash" {
		return errorResult("❌ 'runtime' must be 'python' or 'bash'"), nil
	}

	// Optional args
	scriptName, _ := args["script_name"].(string)

	// Parse secrets
	secrets := make(map[string]string)
	if secretsRaw, ok := args["secrets"].(map[string]interface{}); ok {
		for k, v := range secretsRaw {
			secrets[k] = fmt.Sprintf("%v", v)
		}
	}

	// Parse dependencies
	var dependencies []string
	if depsRaw, ok := args["dependencies"].([]interface{}); ok {
		for _, d := range depsRaw {
			if s, ok := d.(string); ok {
				dependencies = append(dependencies, s)
			}
		}
	}

	// Resolve workspace
	program := e.GetProgram()
	if program == "" {
		return errorResult("❌ No active program. Call set_program first."), nil
	}

	wsMgr := workspace.NewManager(e.config.Config.Workspace.BaseDir)
	ws, err := wsMgr.Get(program)
	if err != nil {
		// Auto-create workspace if it doesn't exist (handles race with set_program)
		ws, err = wsMgr.Create(program)
		if err != nil {
			return errorResult(fmt.Sprintf("❌ Failed to create workspace for program '%s': %v", program, err)), nil
		}
		log.Printf("[SANDBOX] Auto-created workspace for '%s' at %s", program, ws.Path)
	}

	// Execute in sandbox
	return e.ExecuteHuntingScript(ctx, code, runtime, scriptName, secrets, dependencies, ws)
}

// handleLogVectorStatus validates args and writes to MongoDB
func (e *Engine) handleLogVectorStatus(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	vectorID, _ := args["vector_id"].(string)
	if vectorID == "" {
		return errorResult("❌ 'vector_id' is required (e.g., 'IDOR-/api/v1/users/{id}')"), nil
	}

	state, _ := args["state"].(string)
	validStates := map[string]bool{"EXHAUSTED": true, "VULNERABLE": true, "BLOCKED_BY_DESIGN": true}
	if !validStates[state] {
		return errorResult("❌ 'state' must be EXHAUSTED, VULNERABLE, or BLOCKED_BY_DESIGN"), nil
	}

	rationale, _ := args["rationale"].(string)
	if rationale == "" {
		return errorResult("❌ 'rationale' is required — explain why this state was assigned"), nil
	}

	program := e.GetProgram()
	if program == "" {
		return errorResult("❌ No active program. Call set_program first."), nil
	}

	// Write to MongoDB
	if e.config.MongoDB != nil {
		status := &types.VectorStatus{
			Program:   program,
			SessionID: e.getSessionID(),
			Timestamp: time.Now(),
			VectorID:  vectorID,
			State:     state,
			Rationale: rationale,
		}
		if err := e.config.MongoDB.LogVectorStatus(ctx, status); err != nil {
			return errorResult(fmt.Sprintf("❌ Failed to log vector status: %v", err)), nil
		}
	}

	// Build response
	var result strings.Builder
	emoji := "📊"
	switch state {
	case "EXHAUSTED":
		emoji = "✅"
	case "VULNERABLE":
		emoji = "🔴"
	case "BLOCKED_BY_DESIGN":
		emoji = "🚧"
	}

	result.WriteString(fmt.Sprintf("%s Vector Status Logged\n", emoji))
	result.WriteString(fmt.Sprintf("   Vector:    %s\n", vectorID))
	result.WriteString(fmt.Sprintf("   State:     %s\n", state))
	result.WriteString(fmt.Sprintf("   Rationale: %s\n", rationale))
	result.WriteString(fmt.Sprintf("   Program:   %s\n", program))
	result.WriteString("   Saved to MongoDB: ✅\n")

	return successResult(result.String()), nil
}

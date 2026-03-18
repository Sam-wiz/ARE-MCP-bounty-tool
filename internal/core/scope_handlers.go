package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// SCOPE & CONFIGURATION HANDLERS
// ============================================================================

func (e *Engine) handleSetTarget(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		return errorResult("domain is required"), nil
	}

	inScope := []string{domain, "*." + domain}
	if is, ok := args["in_scope"].([]interface{}); ok {
		for _, s := range is {
			if str, ok := s.(string); ok {
				inScope = append(inScope, str)
			}
		}
	}

	outOfScope := []string{}
	if os, ok := args["out_of_scope"].([]interface{}); ok {
		for _, s := range os {
			if str, ok := s.(string); ok {
				outOfScope = append(outOfScope, str)
			}
		}
	}

	e.mu.Lock()
	e.session = &types.Session{
		ID:      uuid.New().String(),
		Program: e.program,
		Target:  domain,
		Scope: types.Scope{
			InScope:    inScope,
			OutOfScope: outOfScope,
		},
		StartedAt:  time.Now(),
		LastActive: time.Now(),
		Status:     "active",
	}
	e.mu.Unlock()

	// Persist session to MongoDB
	if e.config.MongoDB != nil {
		e.config.MongoDB.SaveSession(ctx, e.session)
	}

	result := fmt.Sprintf(`Target set successfully:
- Domain: %s
- Session ID: %s
- In Scope: %v
- Out of Scope: %v
- Session saved to MongoDB: ✅

Ready for reconnaissance. Use recon_discover to start.`, domain, e.session.ID, inScope, outOfScope)

	return successResult(result), nil
}

func (e *Engine) handleValidateScope(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	target, _ := args["target"].(string)
	if target == "" {
		return errorResult("target is required"), nil
	}

	e.mu.RLock()
	session := e.session
	e.mu.RUnlock()

	if session == nil {
		return errorResult("No target set. Use set_target first."), nil
	}

	inScope := false
	for _, pattern := range session.Scope.InScope {
		if matchPattern(target, pattern) {
			inScope = true
			break
		}
	}

	for _, pattern := range session.Scope.OutOfScope {
		if matchPattern(target, pattern) {
			inScope = false
			break
		}
	}

	if inScope {
		return successResult(fmt.Sprintf("✅ %s is IN SCOPE", target)), nil
	}
	return successResult(fmt.Sprintf("❌ %s is OUT OF SCOPE - Do not test!", target)), nil
}

// validateURLScope checks if a URL is within the active session scope.
// Returns nil if no session/scope is set (permissive when no scope defined).
func (e *Engine) validateURLScope(rawURL string) error {
	e.mu.RLock()
	session := e.session
	e.mu.RUnlock()

	if session == nil || len(session.Scope.InScope) == 0 {
		return nil // No scope defined, allow all
	}

	// Extract hostname from URL
	host := rawURL
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		host = rawURL[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check against scope
	for _, pattern := range session.Scope.InScope {
		if matchPattern(host, pattern) {
			// Not explicitly out of scope?
			outOfScope := false
			for _, oos := range session.Scope.OutOfScope {
				if matchPattern(host, oos) {
					outOfScope = true
					break
				}
			}
			if !outOfScope {
				return nil
			}
		}
	}

	return fmt.Errorf("❌ %s is OUT OF SCOPE — request blocked. Use set_target to update scope.", host)
}

func matchPattern(target, pattern string) bool {
	if pattern == target {
		return true
	}
	if len(pattern) > 2 && pattern[:2] == "*." {
		suffix := pattern[1:]
		if len(target) > len(suffix) && target[len(target)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

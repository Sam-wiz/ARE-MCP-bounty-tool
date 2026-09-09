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

	// Make this scope authoritative for enforcement.
	e.setActiveScope(types.Scope{InScope: inScope, OutOfScope: outOfScope})

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

	scope := e.activeScope()
	if len(scope.InScope) == 0 && len(scope.OutOfScope) == 0 {
		return errorResult("No scope set. Use set_program (with in_scope/out_of_scope) or set_target first."), nil
	}

	inScope := false
	for _, pattern := range scope.InScope {
		if matchPattern(target, pattern) {
			inScope = true
			break
		}
	}

	for _, pattern := range scope.OutOfScope {
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
	scope := e.activeScope()
	if len(scope.InScope) == 0 {
		return nil // No scope defined, allow all
	}

	host, _ := splitHostPath(rawURL)

	// Check against scope. Pass the full rawURL (not just host) so that
	// path-scoped entries (e.g. "example.com/testing-path/") are honored —
	// matchPattern does its own host/path parsing on both sides.
	for _, pattern := range scope.InScope {
		if matchPattern(rawURL, pattern) {
			// Not explicitly out of scope?
			outOfScope := false
			for _, oos := range scope.OutOfScope {
				if matchPattern(rawURL, oos) {
					outOfScope = true
					break
				}
			}
			if !outOfScope {
				return nil
			}
		}
	}

	return fmt.Errorf("❌ %s is OUT OF SCOPE — request blocked. Use set_program/set_target to update scope.", host)
}

// splitHostPath splits a raw URL, "host", or "host/path" string into a
// lowercased host and a path that always starts with "/".
func splitHostPath(raw string) (host, path string) {
	s := strings.TrimSpace(raw)
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		host = s[:idx]
		path = s[idx:]
	} else {
		host = s
		path = "/"
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if path == "" {
		path = "/"
	}
	return strings.ToLower(host), path
}

// hasExplicitPath reports whether raw (a URL or "host/path" scope entry)
// contains a path component at all, as opposed to being a bare host/wildcard.
func hasExplicitPath(raw string) bool {
	s := strings.TrimSpace(raw)
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	return strings.Contains(s, "/")
}

// matchPattern reports whether target (a URL, bare host, or "host/path"
// string) matches pattern (a scope entry). A "*.example.com" host pattern
// matches any subdomain AND the apex "example.com". A pattern with no path
// component matches the host under ANY path. A pattern that does include a
// path (e.g. "example.com/testing-path/") additionally requires the
// target's path to start with that pattern's path — this is what lets a
// scope entry authorize one specific path on a host without opening up the
// whole domain.
func matchPattern(target, pattern string) bool {
	targetHost, targetPath := splitHostPath(target)
	patternHost, patternPath := splitHostPath(pattern)

	hostMatch := patternHost == targetHost
	if !hostMatch && strings.HasPrefix(patternHost, "*.") {
		apex := patternHost[2:] // "example.com"
		hostMatch = targetHost == apex || strings.HasSuffix(targetHost, "."+apex)
	}
	if !hostMatch {
		return false
	}

	if !hasExplicitPath(pattern) {
		return true // host-level scope entry: any path matches
	}
	return strings.HasPrefix(targetPath, patternPath)
}

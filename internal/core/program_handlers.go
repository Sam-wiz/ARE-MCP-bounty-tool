package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
	"github.com/samrudh/hack-ai-v2/internal/workspace"
)

// ============================================================================
// BOUNTY PROGRAM MANAGEMENT HANDLERS
// ============================================================================

func (e *Engine) handleSetProgram(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	slug, _ := args["slug"].(string)
	if slug == "" {
		return errorResult("slug is required (e.g., 'playtika', 'hackerone-xyz')"), nil
	}

	name, _ := args["name"].(string)
	if name == "" {
		name = slug
	}

	platform, _ := args["platform"].(string)
	if platform == "" {
		platform = "independent"
	}

	url, _ := args["url"].(string)

	// Set active program
	e.mu.Lock()
	e.program = slug
	e.mu.Unlock()

	// -----------------------------------------------------------
	// Create/verify workspace directory under bounties/
	// This is the filesystem workspace that execute_hunting_script
	// and other sandbox tools depend on.
	// -----------------------------------------------------------
	baseDir := ""
	if e.config.Config != nil {
		baseDir = e.config.Config.Workspace.BaseDir
	}
	wsMgr := workspace.NewManager(baseDir)
	ws, err := wsMgr.Get(slug)
	if err != nil {
		// Workspace doesn't exist yet — create it
		ws, err = wsMgr.Create(slug)
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to create workspace for '%s': %v", slug, err)), nil
		}
		log.Printf("[SET_PROGRAM] Created new workspace at %s", ws.Path)
	} else {
		log.Printf("[SET_PROGRAM] Using existing workspace at %s", ws.Path)
	}

	// Build program object
	program := &types.BountyProgram{
		ID:         slug,
		Slug:       slug,
		Name:       name,
		Platform:   platform,
		URL:        url,
		Status:     "active",
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	// Parse scope if provided
	if inScope, ok := args["in_scope"].([]interface{}); ok {
		for _, s := range inScope {
			if str, ok := s.(string); ok {
				program.Scope.InScope = append(program.Scope.InScope, str)
			}
		}
	}
	if outOfScope, ok := args["out_of_scope"].([]interface{}); ok {
		for _, s := range outOfScope {
			if str, ok := s.(string); ok {
				program.Scope.OutOfScope = append(program.Scope.OutOfScope, str)
			}
		}
	}

	// Make the program's scope authoritative for enforcement immediately —
	// so tools are scope-guarded even before set_target is called.
	if len(program.Scope.InScope) > 0 || len(program.Scope.OutOfScope) > 0 {
		e.setActiveScope(program.Scope)
	}

	// Parse payout
	if min, ok := args["payout_min"].(float64); ok {
		program.PayoutMin = int(min)
	}
	if max, ok := args["payout_max"].(float64); ok {
		program.PayoutMax = int(max)
	}

	// Parse notes
	if notes, ok := args["notes"].(string); ok {
		program.Notes = notes
	}

	// Persist to MongoDB
	mongoStatus := "⚠️ MongoDB not configured"
	if e.config.MongoDB != nil {
		// Check if program already exists
		existing, _ := e.config.MongoDB.GetProgram(ctx, slug)
		if existing != nil {
			// Reactivate, but don't silently discard newly-passed fields —
			// callers legitimately need to correct/extend scope on an
			// already-registered program.
			existing.LastActive = time.Now()
			existing.Status = "active"
			if name != slug {
				existing.Name = name
			}
			if url != "" {
				existing.URL = url
			}
			if len(program.Scope.InScope) > 0 {
				existing.Scope.InScope = program.Scope.InScope
			}
			if len(program.Scope.OutOfScope) > 0 {
				existing.Scope.OutOfScope = program.Scope.OutOfScope
			}
			if program.PayoutMin > 0 {
				existing.PayoutMin = program.PayoutMin
			}
			if program.PayoutMax > 0 {
				existing.PayoutMax = program.PayoutMax
			}
			if program.Notes != "" {
				existing.Notes = program.Notes
			}
			e.config.MongoDB.SaveProgram(ctx, existing)
			if len(existing.Scope.InScope) > 0 || len(existing.Scope.OutOfScope) > 0 {
				e.setActiveScope(existing.Scope)
			}
			return successResult(fmt.Sprintf("🎯 Switched to existing program: %s\n- Platform: %s\n- Status: active\n- Workspace: %s\n- In Scope: %v\n- Out of Scope: %v\n- All new findings/sessions will be tagged with program: %s", existing.Name, existing.Platform, ws.Path, existing.Scope.InScope, existing.Scope.OutOfScope, slug)), nil
		}

		if err := e.config.MongoDB.SaveProgram(ctx, program); err != nil {
			mongoStatus = fmt.Sprintf("⚠️ MongoDB save failed: %v", err)
		} else {
			mongoStatus = "✅"
		}
	}

	return successResult(fmt.Sprintf(`🎯 Bounty program created and set:
- Slug: %s
- Name: %s
- Platform: %s
- Status: active
- Workspace: %s
- Saved to MongoDB: %s

All findings, sessions, and tool runs will now be tagged with program: "%s"
Use set_target to set the target domain.`, slug, name, platform, ws.Path, mongoStatus, slug)), nil
}

func (e *Engine) handleListPrograms(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	if e.config.MongoDB == nil {
		return errorResult("MongoDB not configured"), nil
	}

	programs, err := e.config.MongoDB.ListPrograms(ctx)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to list programs: %v", err)), nil
	}

	if len(programs) == 0 {
		return successResult("No bounty programs registered yet. Use set_program to create one."), nil
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("📋 Bounty Programs (%d total)\n\n", len(programs)))

	for _, p := range programs {
		active := ""
		if p.Slug == e.GetProgram() {
			active = " ← ACTIVE"
		}
		result.WriteString(fmt.Sprintf("🎯 %s (%s)%s\n", p.Name, p.Slug, active))
		result.WriteString(fmt.Sprintf("   Platform: %s | Status: %s\n", p.Platform, p.Status))
		if p.URL != "" {
			result.WriteString(fmt.Sprintf("   URL: %s\n", p.URL))
		}
		if p.PayoutMax > 0 {
			result.WriteString(fmt.Sprintf("   Payout: $%d - $%d\n", p.PayoutMin, p.PayoutMax))
		}
		result.WriteString(fmt.Sprintf("   Last active: %s\n\n", p.LastActive.Format("2006-01-02 15:04")))
	}

	return successResult(result.String()), nil
}

func (e *Engine) handleProgramStats(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	if e.config.MongoDB == nil {
		return errorResult("MongoDB not configured"), nil
	}

	program, _ := args["program"].(string)
	if program == "" {
		program = e.GetProgram()
	}
	if program == "" {
		return errorResult("No active program. Use set_program first or pass program slug."), nil
	}

	stats, err := e.config.MongoDB.GetProgramStats(ctx, program)
	if err != nil {
		return errorResult(fmt.Sprintf("Failed to get stats: %v", err)), nil
	}

	data, _ := json.MarshalIndent(stats, "", "  ")

	var result strings.Builder
	result.WriteString(fmt.Sprintf("📊 Program Stats: %s\n\n", program))
	result.WriteString(string(data))

	// Also get recent findings
	findings, _ := e.config.MongoDB.GetFindingsByProgram(ctx, program)
	if len(findings) > 0 {
		result.WriteString(fmt.Sprintf("\n\n--- Recent Findings (%d total) ---\n", len(findings)))
		limit := 10
		if len(findings) < limit {
			limit = len(findings)
		}
		for i := 0; i < limit; i++ {
			f := findings[i]
			result.WriteString(fmt.Sprintf("  [%s] %s — %s (%s)\n", f.Severity, f.Title, f.VulnType, f.State))
		}
	}

	return successResult(result.String()), nil
}

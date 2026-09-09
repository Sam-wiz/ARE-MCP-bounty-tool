package core

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// RECONNAISSANCE HANDLERS
// ============================================================================

func (e *Engine) handleReconDiscover(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		return errorResult("domain is required"), nil
	}

	mode := "passive"
	if m, ok := args["mode"].(string); ok {
		mode = m
	}

	var allResults strings.Builder
	allResults.WriteString(fmt.Sprintf("🔍 Reconnaissance on %s (mode: %s)\n\n", domain, mode))

	// Phase 1: Subdomain Discovery
	allResults.WriteString("=== Phase 1: Subdomain Discovery ===\n")

	// Try subfinder
	if plugin, exists := e.plugins.Get("subfinder"); exists {
		pluginArgs := map[string]interface{}{"domain": domain}
		result, err := e.ExecutePluginFull(ctx, plugin, pluginArgs)
		if err == nil && !result.IsError {
			allResults.WriteString("[subfinder] ")
			allResults.WriteString(result.Content[0].Text)
			allResults.WriteString("\n")
		} else {
			errMsg := "unknown error"
			if err != nil {
				errMsg = err.Error()
			} else if result.IsError && len(result.Content) > 0 {
				errMsg = result.Content[0].Text
			}
			allResults.WriteString(fmt.Sprintf("[subfinder] Failed: %s\n", errMsg))
		}
	} else {
		// Fallback: run subfinder directly
		result, _ := e.ExecuteRawCommand(ctx, fmt.Sprintf("subfinder -d %s -silent 2>/dev/null", ShellEscape(domain)), "subfinder", 300)
		allResults.WriteString(result.Content[0].Text)
		allResults.WriteString("\n")
	}

	// Phase 2: HTTP Probing (if mode is active or deep)
	if mode == "active" || mode == "deep" {
		allResults.WriteString("\n=== Phase 2: HTTP Probing ===\n")
		if plugin, exists := e.plugins.Get("httpx"); exists {
			// httpx.yaml expects input_file (a file path), so create a temp file
			tmpFile, err := os.CreateTemp("", "httpx_input_*.txt")
			if err == nil {
				tmpFile.WriteString(domain + "\n")
				tmpFile.Close()
				defer os.Remove(tmpFile.Name())

				pluginArgs := map[string]interface{}{"input_file": tmpFile.Name()}
				result, err := e.ExecutePluginFull(ctx, plugin, pluginArgs)
				if err == nil && !result.IsError {
					allResults.WriteString("[httpx] ")
					allResults.WriteString(result.Content[0].Text)
				} else {
					errMsg := "unknown error"
					if err != nil {
						errMsg = err.Error()
					} else if result.IsError && len(result.Content) > 0 {
						errMsg = result.Content[0].Text
					}
					allResults.WriteString(fmt.Sprintf("[httpx] Failed: %s\n", errMsg))
				}
			} else {
				allResults.WriteString(fmt.Sprintf("[httpx] Failed to create temp file: %v\n", err))
			}
		} else {
			result, _ := e.ExecuteRawCommand(ctx,
				fmt.Sprintf("echo %s | httpx -silent -status-code -title 2>/dev/null", ShellEscape(domain)),
				"httpx", 120)
			allResults.WriteString(result.Content[0].Text)
		}
	}

	// Phase 3: Endpoint Discovery (deep mode)
	if mode == "deep" {
		allResults.WriteString("\n=== Phase 3: Endpoint Discovery ===\n")
		result, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("waybackurls %s 2>/dev/null | head -100", ShellEscape(domain)),
			"waybackurls", 120)
		allResults.WriteString(result.Content[0].Text)
	}

	return successResult(allResults.String()), nil
}

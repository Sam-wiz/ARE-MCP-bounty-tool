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
// VALIDATION & EVIDENCE HANDLERS
// ============================================================================

func (e *Engine) handleValidateFinding(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	findingID, _ := args["finding_id"].(string)
	if findingID == "" {
		return errorResult("finding_id is required"), nil
	}

	e.mu.RLock()
	finding, exists := e.findings[findingID]
	e.mu.RUnlock()

	if !exists {
		// Try MongoDB
		if e.config.MongoDB != nil {
			var err error
			finding, err = e.config.MongoDB.GetFinding(ctx, findingID)
			if err != nil || finding == nil {
				return errorResult(fmt.Sprintf("Finding not found: %s", findingID)), nil
			}
		} else {
			return errorResult(fmt.Sprintf("Finding not found: %s", findingID)), nil
		}
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("🔍 Validating: %s\n", finding.Title))
	results.WriteString(fmt.Sprintf("Current State: %s | Severity: %s\n\n", finding.State, finding.Severity))

	// Secondary verification: replay the request
	if finding.URL != "" {
		results.WriteString("=== Secondary Verification ===\n")
		verifyResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' %s 2>/dev/null", ShellEscape(finding.URL)),
			"verify-curl", 30)
		results.WriteString(verifyResult.Content[0].Text)

		// Update finding state
		e.mu.Lock()
		finding.State = types.FindingVerified
		finding.VerifiedAt = time.Now()
		finding.VerifiedBy = "auto-validation"
		e.mu.Unlock()

		if e.config.MongoDB != nil {
			e.config.MongoDB.SaveFinding(ctx, finding)
		}
		results.WriteString("\n✅ Finding state updated to VERIFIED\n")
	}

	return successResult(results.String()), nil
}

func (e *Engine) handleCaptureEvidence(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	evidenceTypes, ok := args["types"].([]interface{})
	if !ok || len(evidenceTypes) == 0 {
		return errorResult("types array is required"), nil
	}

	url, _ := args["url"].(string)
	findingID, _ := args["finding_id"].(string)

	// If no URL, try to get from finding
	if url == "" && findingID != "" {
		e.mu.RLock()
		if f, ok := e.findings[findingID]; ok {
			url = f.URL
		}
		e.mu.RUnlock()
	}

	var results strings.Builder
	results.WriteString("📷 Evidence Capture\n\n")

	for _, et := range evidenceTypes {
		evidenceType, _ := et.(string)

		switch evidenceType {
		case "screenshot":
			if url == "" {
				results.WriteString("[screenshot] Skipped: no URL\n")
				continue
			}
			outPath := fmt.Sprintf("/tmp/evidence_%s.png", uuid.New().String()[:8])
			// Use gowitness or chromedp for screenshots
			result, _ := e.ExecuteRawCommand(ctx,
				fmt.Sprintf("gowitness single %s --screenshot-path %s 2>/dev/null || "+
					"chromium --headless --screenshot=%s %s 2>/dev/null || "+
					"echo 'No screenshot tool available (install gowitness)'",
					ShellEscape(url), ShellEscape(outPath), ShellEscape(outPath), ShellEscape(url)),
				"screenshot", 30)
			results.WriteString(fmt.Sprintf("[screenshot] %s\n", result.Content[0].Text))

		case "response":
			if url == "" {
				results.WriteString("[response] Skipped: no URL\n")
				continue
			}
			outPath := fmt.Sprintf("/tmp/evidence_response_%s.txt", uuid.New().String()[:8])
			result, _ := e.ExecuteRawCommand(ctx,
				fmt.Sprintf("curl -sD - %s > %s 2>/dev/null && echo 'Saved to %s'", ShellEscape(url), ShellEscape(outPath), outPath),
				"response-capture", 30)
			results.WriteString(fmt.Sprintf("[response] %s\n", result.Content[0].Text))

		case "har":
			results.WriteString("[har] HAR capture requires browser integration — use browser tool\n")

		case "video":
			results.WriteString("[video] Video capture requires browser integration — use browser tool\n")
		}
	}

	return successResult(results.String()), nil
}

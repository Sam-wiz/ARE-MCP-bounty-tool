package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// STATE & REPORTING HANDLERS
// ============================================================================

func (e *Engine) handleGetFindings(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stateFilter, _ := args["state"].(string)
	severityFilter, _ := args["severity"].(string)

	findings := make([]*types.Finding, 0)
	for _, f := range e.findings {
		if stateFilter != "" && string(f.State) != stateFilter {
			continue
		}
		if severityFilter != "" && f.Severity != severityFilter {
			continue
		}
		findings = append(findings, f)
	}

	// Also try MongoDB if we have it and in-memory is empty
	if len(findings) == 0 && e.config.MongoDB != nil {
		if stateFilter != "" {
			dbFindings, err := e.config.MongoDB.GetFindingsByState(ctx, types.FindingState(stateFilter))
			if err == nil {
				findings = dbFindings
			}
		}
	}

	if len(findings) == 0 {
		return successResult("No findings match the criteria"), nil
	}

	data, _ := json.MarshalIndent(findings, "", "  ")
	return successResult(string(data)), nil
}

func (e *Engine) handleGenerateReport(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	format := "markdown"
	if f, ok := args["format"].(string); ok {
		format = f
	}

	platform := "generic"
	if p, ok := args["platform"].(string); ok {
		platform = p
	}

	e.mu.RLock()
	findings := make([]*types.Finding, 0, len(e.findings))
	for _, f := range e.findings {
		findings = append(findings, f)
	}
	session := e.session
	e.mu.RUnlock()

	if len(findings) == 0 {
		return successResult("No findings to report. Run scans first."), nil
	}

	var report strings.Builder

	switch format {
	case "markdown":
		report.WriteString(generateMarkdownReport(findings, session, platform))
	case "json":
		data, _ := json.MarshalIndent(findings, "", "  ")
		report.Write(data)
	default:
		report.WriteString(generateMarkdownReport(findings, session, platform))
	}

	return successResult(report.String()), nil
}

// generateMarkdownReport creates a professional vulnerability report
func generateMarkdownReport(findings []*types.Finding, session *types.Session, platform string) string {
	var r strings.Builder

	// Header
	target := "Unknown"
	if session != nil {
		target = session.Target
	}

	r.WriteString(fmt.Sprintf("# Vulnerability Report: %s\n\n", target))
	r.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().Format(time.RFC3339)))
	r.WriteString(fmt.Sprintf("**Platform:** %s\n", platform))
	r.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(findings)))

	// Summary by severity
	severityCounts := map[string]int{}
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		severityCounts[sev]++
	}

	r.WriteString("## Summary\n\n")
	r.WriteString("| Severity | Count |\n|----------|-------|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := severityCounts[sev]; ok {
			r.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
		}
	}
	r.WriteString("\n---\n\n")

	// Individual findings
	r.WriteString("## Findings\n\n")
	for i, f := range findings {
		r.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
		r.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		r.WriteString(fmt.Sprintf("- **State:** %s\n", f.State))
		r.WriteString(fmt.Sprintf("- **Type:** %s\n", f.VulnType))
		if f.URL != "" {
			r.WriteString(fmt.Sprintf("- **URL:** %s\n", f.URL))
		}
		if f.Description != "" {
			r.WriteString(fmt.Sprintf("\n**Description:** %s\n", f.Description))
		}
		if f.PoC != nil && f.PoC.CurlCommand != "" {
			r.WriteString(fmt.Sprintf("\n**PoC:**\n```bash\n%s\n```\n", f.PoC.CurlCommand))
		}
		if f.CWE != "" {
			r.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CWE))
		}
		r.WriteString("\n---\n\n")
	}

	return r.String()
}

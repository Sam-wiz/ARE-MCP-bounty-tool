package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// API, HTTP & TOOL EXECUTION HANDLERS
// ============================================================================

// handleIngestResult allows the LLM to push ad-hoc findings into the system
func (e *Engine) handleIngestResult(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	title, _ := args["title"].(string)
	if title == "" {
		return errorResult("title is required"), nil
	}

	severity, _ := args["severity"].(string)
	if severity == "" {
		severity = "info"
	}

	finding := &types.Finding{
		ID:         uuid.New().String()[:8],
		Program:    e.GetProgram(),
		State:      types.FindingDetected,
		Title:      title,
		Severity:   severity,
		DetectedBy: "manual-ingest",
		DetectedAt: time.Now(),
		Tags:       []string{"manual"},
	}

	// Optional fields
	if desc, ok := args["description"].(string); ok {
		finding.Description = desc
	}
	if url, ok := args["url"].(string); ok {
		finding.URL = url
	}
	if vulnType, ok := args["vuln_type"].(string); ok {
		finding.VulnType = vulnType
	}
	if endpoint, ok := args["endpoint"].(string); ok {
		finding.Endpoint = endpoint
	}
	if method, ok := args["method"].(string); ok {
		finding.Method = method
	}
	if payload, ok := args["payload"].(string); ok {
		finding.Payload = payload
	}
	if cwe, ok := args["cwe"].(string); ok {
		finding.CWE = cwe
	}
	if owasp, ok := args["owasp"].(string); ok {
		finding.OWASP = owasp
	}
	if rawOutput, ok := args["raw_output"].(string); ok {
		finding.RawOutput = rawOutput
	}
	if curlCmd, ok := args["curl_command"].(string); ok {
		finding.PoC = &types.PoC{
			Type:        "http",
			CurlCommand: curlCmd,
		}
	}
	if tags, ok := args["tags"].([]interface{}); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				finding.Tags = append(finding.Tags, s)
			}
		}
	}

	// Store in memory
	e.mu.Lock()
	e.findings[finding.ID] = finding
	e.mu.Unlock()

	// Persist to MongoDB
	if e.config.MongoDB != nil {
		if err := e.config.MongoDB.SaveFinding(ctx, finding); err != nil {
			return errorResult(fmt.Sprintf("Saved in memory but MongoDB failed: %v", err)), nil
		}
	}

	return successResult(fmt.Sprintf("✅ Finding ingested:\n- ID: %s\n- Title: %s\n- Severity: %s\n- Saved to MongoDB: ✅\n\nUse validate_finding to verify, or get_findings to list all.",
		finding.ID, finding.Title, finding.Severity)), nil
}

// handleRunTool executes a specific plugin by name with provided arguments
func (e *Engine) handleRunTool(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	toolName, _ := args["name"].(string)
	if toolName == "" {
		return errorResult("name is required"), nil
	}

	plugin, exists := e.plugins.Get(toolName)
	if !exists {
		// List available plugins
		allPlugins := e.plugins.GetAll()
		var names []string
		for _, p := range allPlugins {
			names = append(names, fmt.Sprintf("%s (%s)", p.Name, p.Category))
		}
		return errorResult(fmt.Sprintf("Plugin not found: %s\nAvailable: %s", toolName, strings.Join(names, ", "))), nil
	}

	// Pass through all other args to the plugin
	pluginArgs := make(map[string]interface{})
	for k, v := range args {
		if k != "name" {
			pluginArgs[k] = v
		}
	}

	// Scope enforcement on any URL/host/target arg the plugin receives.
	if err := e.validateArgsScope(pluginArgs); err != nil {
		return errorResult(err.Error()), nil
	}

	return e.ExecutePluginFull(ctx, plugin, pluginArgs)
}

// handleAPITest performs authenticated API testing (IDOR detection, auth bypass)
func (e *Engine) handleAPITest(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	url1, _ := args["url"].(string)
	if url1 == "" {
		return errorResult("url is required"), nil
	}

	// Scope enforcement (not just http_request).
	if err := e.validateURLScope(url1); err != nil {
		return errorResult(err.Error()), nil
	}

	method := "GET"
	if m, ok := args["method"].(string); ok {
		method = strings.ToUpper(m)
	}

	// Build headers (shell-escaped)
	headerFlags := ""
	if headers, ok := args["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			headerFlags += fmt.Sprintf(" -H %s", ShellEscape(fmt.Sprintf("%s: %s", k, v)))
		}
	}
	if auth, ok := args["authorization"].(string); ok {
		headerFlags += fmt.Sprintf(" -H %s", ShellEscape(fmt.Sprintf("Authorization: %s", auth)))
	}

	// Build body (shell-escaped)
	bodyFlag := ""
	if body, ok := args["body"].(string); ok {
		bodyFlag = fmt.Sprintf(" -d %s", ShellEscape(body))
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("🔐 API Test: %s %s\n\n", method, url1))

	// Request 1: Main request (egress through the configured proxy)
	cmd1 := fmt.Sprintf("curl -s%s -w '\\n---HTTP_CODE:%%{http_code}---' -X %s%s%s %s 2>/dev/null",
		e.curlProxyArg(), method, headerFlags, bodyFlag, ShellEscape(url1))
	result1, _ := e.ExecuteRawCommand(ctx, cmd1, "api-test", 30)
	results.WriteString("=== Response ===\n")
	results.WriteString(result1.Content[0].Text)

	// If compare_url provided, do differential analysis
	if url2, ok := args["compare_url"].(string); ok && url2 != "" {
		results.WriteString("\n\n=== Comparison Request ===\n")
		cmd2 := fmt.Sprintf("curl -s%s -w '\\n---HTTP_CODE:%%{http_code}---' -X %s%s%s %s 2>/dev/null",
			e.curlProxyArg(), method, headerFlags, bodyFlag, ShellEscape(url2))
		result2, _ := e.ExecuteRawCommand(ctx, cmd2, "api-test-compare", 30)
		results.WriteString(result2.Content[0].Text)

		// Simple diff
		results.WriteString("\n\n=== Differential Analysis ===\n")
		if result1.Content[0].Text == result2.Content[0].Text {
			results.WriteString("⚠️  Responses are IDENTICAL — may indicate template/generic response\n")
		} else {
			results.WriteString("🔴 Responses DIFFER — potential IDOR confirmed!\n")
		}
	}

	// No-auth test
	if _, ok := args["test_no_auth"].(bool); ok {
		results.WriteString("\n\n=== No-Auth Test ===\n")
		cmdNoAuth := fmt.Sprintf("curl -s -w '\\n---HTTP_CODE:%%{http_code}---' -X %s %s 2>/dev/null",
			method, ShellEscape(url1))
		resultNoAuth, _ := e.ExecuteRawCommand(ctx, cmdNoAuth, "api-test-noauth", 30)
		results.WriteString(resultNoAuth.Content[0].Text)

		// Check if we can access without auth
		noAuthOutput := resultNoAuth.Content[0].Text
		if strings.Contains(noAuthOutput, "HTTP_CODE:200") || strings.Contains(noAuthOutput, "HTTP_CODE:201") {
			results.WriteString("\n🔴 CRITICAL: Endpoint accessible WITHOUT authentication!\n")

			// Auto-ingest as finding
			finding := &types.Finding{
				ID:         uuid.New().String()[:8],
				State:      types.FindingDetected,
				Title:      fmt.Sprintf("Missing Authentication: %s %s", method, url1),
				Severity:   "high",
				VulnType:   "broken-access-control",
				URL:        url1,
				Method:     method,
				DetectedBy: "api-test",
				DetectedAt: time.Now(),
				OWASP:      "A01:2021",
				CWE:        "CWE-306",
				Tags:       []string{"auth-bypass", "api"},
			}
			e.mu.Lock()
			e.findings[finding.ID] = finding
			e.mu.Unlock()
			if e.config.MongoDB != nil {
				e.config.MongoDB.SaveFinding(ctx, finding)
			}
			results.WriteString(fmt.Sprintf("📦 Auto-ingested as finding %s\n", finding.ID))
		}
	}

	return successResult(results.String()), nil
}

// handleHTTPRequest is a simple HTTP request tool for testing
func (e *Engine) handleHTTPRequest(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	url, _ := args["url"].(string)
	if url == "" {
		return errorResult("url is required"), nil
	}

	// Scope validation: if a session with scope is active, only allow in-scope targets
	if err := e.validateURLScope(url); err != nil {
		return errorResult(err.Error()), nil
	}

	method := "GET"
	if m, ok := args["method"].(string); ok {
		method = strings.ToUpper(m)
	}

	// Check if URL returns actual data (egress through the configured proxy)
	client := e.newHTTPClient(15 * time.Second)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return errorResult(fmt.Sprintf("Invalid request: %v", err)), nil
	}

	// Add headers
	if headers, ok := args["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			req.Header.Set(k, fmt.Sprintf("%v", v))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return errorResult(fmt.Sprintf("Request failed: %v", err)), nil
	}
	defer resp.Body.Close()

	var body strings.Builder
	buf := make([]byte, 5000)
	n, _ := resp.Body.Read(buf)
	body.Write(buf[:n])

	var result strings.Builder
	result.WriteString(fmt.Sprintf("📡 %s %s → %d %s\n\n", method, url, resp.StatusCode, resp.Status))
	result.WriteString("--- Response Headers ---\n")
	for k, v := range resp.Header {
		result.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	result.WriteString(fmt.Sprintf("\n--- Body (%d bytes) ---\n", n))
	result.WriteString(body.String())

	return successResult(result.String()), nil
}

// ============================================================================
// PLUGIN EXECUTION (delegates to real executor)
// ============================================================================

func (e *Engine) executePlugin(ctx context.Context, plugin *types.PluginDefinition, args map[string]interface{}) (types.ToolResult, error) {
	return e.ExecutePluginFull(ctx, plugin, args)
}

package core

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// SCANNING & INJECTION HANDLERS
// ============================================================================

func (e *Engine) handleScanVulnerabilities(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	targets, ok := args["targets"].([]interface{})
	if !ok || len(targets) == 0 {
		return errorResult("targets array is required"), nil
	}

	// Build nuclei command
	targetList := make([]string, len(targets))
	for i, t := range targets {
		targetList[i] = fmt.Sprintf("%v", t)
	}

	// Build severity filter
	severityFlag := ""
	if sev, ok := args["severity"].([]interface{}); ok && len(sev) > 0 {
		parts := make([]string, len(sev))
		for i, s := range sev {
			parts[i] = fmt.Sprintf("%v", s)
		}
		severityFlag = fmt.Sprintf("-severity %s", strings.Join(parts, ","))
	}

	// Build tags filter
	tagsFlag := ""
	if tags, ok := args["tags"].([]interface{}); ok && len(tags) > 0 {
		parts := make([]string, len(tags))
		for i, t := range tags {
			parts[i] = fmt.Sprintf("%v", t)
		}
		tagsFlag = fmt.Sprintf("-tags %s", strings.Join(parts, ","))
	}

	// Try nuclei plugin first
	if plugin, exists := e.plugins.Get("nuclei"); exists {
		// Create temp file for targets
		tmpFile, err := os.CreateTemp("", "nuclei_targets_*.txt")
		if err != nil {
			return errorResult(fmt.Sprintf("Failed to create temp targets file: %v", err)), nil
		}
		defer os.Remove(tmpFile.Name()) // Clean up

		if _, err := tmpFile.WriteString(strings.Join(targetList, "\n")); err != nil {
			return errorResult(fmt.Sprintf("Failed to write targets to temp file: %v", err)), nil
		}
		if err := tmpFile.Close(); err != nil {
			return errorResult(fmt.Sprintf("Failed to close temp targets file: %v", err)), nil
		}

		pluginArgs := map[string]interface{}{
			"targets_file": tmpFile.Name(),
			"severity":     strings.Join(strings.Split(strings.TrimPrefix(severityFlag, "-severity "), ","), ","),
		}
		// If severity was empty, use default or empty string
		if severityFlag == "" {
			pluginArgs["severity"] = "critical,high,medium,low,info"
		}

		return e.ExecutePluginFull(ctx, plugin, pluginArgs)
	}

	// Fallback: raw nuclei command
	cmd := fmt.Sprintf("echo %s | nuclei -j %s %s 2>/dev/null",
		ShellEscape(strings.Join(targetList, "\n")), severityFlag, tagsFlag)

	return e.ExecuteRawCommand(ctx, cmd, "nuclei", 600)
}

func (e *Engine) handleTestInjection(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	urls, ok := args["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return errorResult("urls array is required"), nil
	}

	injectionTypes := []string{"xss"}
	if t, ok := args["types"].([]interface{}); ok {
		injectionTypes = make([]string, len(t))
		for i, v := range t {
			injectionTypes[i], _ = v.(string)
		}
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("🧪 Injection testing on %d URLs\nTypes: %v\n\n", len(urls), injectionTypes))

	for _, injType := range injectionTypes {
		results.WriteString(fmt.Sprintf("=== Testing: %s ===\n", injType))

		for _, u := range urls {
			url := fmt.Sprintf("%v", u)

			switch injType {
			case "xss":
				if plugin, exists := e.plugins.Get("dalfox"); exists {
					pluginArgs := map[string]interface{}{"url": url}
					result, err := e.ExecutePluginFull(ctx, plugin, pluginArgs)
					if err == nil && !result.IsError {
						results.WriteString(result.Content[0].Text)
					} else {
						errMsg := "unknown error"
						if err != nil {
							errMsg = err.Error()
						} else if result.IsError && len(result.Content) > 0 {
							errMsg = result.Content[0].Text
						}
						results.WriteString(fmt.Sprintf("[dalfox] Failed: %s\n", errMsg))
					}
				} else {
					result, _ := e.ExecuteRawCommand(ctx,
						fmt.Sprintf("dalfox url %s --silence 2>/dev/null", ShellEscape(url)),
						"dalfox", 300)
					results.WriteString(result.Content[0].Text)
				}

			case "sqli":
				if plugin, exists := e.plugins.Get("sqlmap"); exists {
					pluginArgs := map[string]interface{}{"url": url}
					result, err := e.ExecutePluginFull(ctx, plugin, pluginArgs)
					if err == nil && !result.IsError {
						results.WriteString(result.Content[0].Text)
					} else {
						errMsg := "unknown error"
						if err != nil {
							errMsg = err.Error()
						} else if result.IsError && len(result.Content) > 0 {
							errMsg = result.Content[0].Text
						}
						results.WriteString(fmt.Sprintf("[sqlmap] Failed: %s\n", errMsg))
					}
				} else {
					result, _ := e.ExecuteRawCommand(ctx,
						fmt.Sprintf("sqlmap -u %s --batch --level 1 --risk 1 2>/dev/null", ShellEscape(url)),
						"sqlmap", 300)
					results.WriteString(result.Content[0].Text)
				}

			default:
				results.WriteString(fmt.Sprintf("Tool for %s not configured\n", injType))
			}
			results.WriteString("\n")
		}
	}

	return successResult(results.String()), nil
}

func (e *Engine) handleTestCloud(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	target, _ := args["target"].(string)
	if target == "" {
		return errorResult("target is required"), nil
	}

	provider := "auto"
	if p, ok := args["provider"].(string); ok {
		provider = p
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("☁️  Cloud testing: %s (provider: %s)\n\n", target, provider))

	// S3 bucket check
	results.WriteString("=== S3 Bucket Check ===\n")
	s3cmd := fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' %s 2>/dev/null", ShellEscape(fmt.Sprintf("https://%s.s3.amazonaws.com/", target)))
	result, _ := e.ExecuteRawCommand(ctx, s3cmd, "s3-check", 30)
	results.WriteString(result.Content[0].Text)

	// GCS bucket check
	results.WriteString("\n\n=== GCS Bucket Check ===\n")
	gcsCmd := fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' %s 2>/dev/null", ShellEscape(fmt.Sprintf("https://storage.googleapis.com/%s/", target)))
	result, _ = e.ExecuteRawCommand(ctx, gcsCmd, "gcs-check", 30)
	results.WriteString(result.Content[0].Text)

	return successResult(results.String()), nil
}

func (e *Engine) handleFuzzTarget(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	target, _ := args["target"].(string)
	fuzzType, _ := args["type"].(string)

	if target == "" || fuzzType == "" {
		return errorResult("target and type are required"), nil
	}

	wordlist, _ := args["wordlist"].(string)
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
	}

	duration := 0
	if d, ok := args["duration"].(float64); ok {
		duration = int(d)
	}

	switch fuzzType {
	case "http":
		if plugin, exists := e.plugins.Get("ffuf"); exists {
			pluginArgs := map[string]interface{}{
				"url":      target,
				"wordlist": wordlist,
			}
			return e.ExecutePluginFull(ctx, plugin, pluginArgs)
		}

		cmd := fmt.Sprintf("ffuf -u %s -w %s -mc 200,301,302,403 -json 2>/dev/null | head -100",
			ShellEscape(target+"/FUZZ"), ShellEscape(wordlist))
		timeout := 300
		if duration > 0 {
			timeout = duration * 60
		}
		return e.ExecuteRawCommand(ctx, cmd, "ffuf", timeout)

	case "api":
		cmd := fmt.Sprintf("ffuf -u %s -w %s -mc 200,201,204,301,302,401,403,405 -json 2>/dev/null | head -100",
			ShellEscape(target+"/FUZZ"), ShellEscape(wordlist))
		return e.ExecuteRawCommand(ctx, cmd, "ffuf-api", 300)

	default:
		return errorResult(fmt.Sprintf("Unsupported fuzz type: %s (supported: http, api)", fuzzType)), nil
	}
}

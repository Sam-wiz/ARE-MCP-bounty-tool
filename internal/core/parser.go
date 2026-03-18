// Package core - parser.go implements generic output parsing for tool plugins
package core

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ParseResult holds the parsed output from a tool execution
type ParseResult struct {
	Findings  []*types.Finding
	RawLines  []string
	ItemCount int
	ParseType string
}

// ParseToolOutput parses raw command output using the plugin's parse configuration
func ParseToolOutput(plugin *types.PluginDefinition, rawOutput string, sessionID string) (*ParseResult, error) {
	result := &ParseResult{
		RawLines:  strings.Split(rawOutput, "\n"),
		ParseType: plugin.Parse.Type,
	}

	switch plugin.Parse.Type {
	case "json":
		findings, err := parseJSON(plugin, rawOutput, sessionID)
		if err != nil {
			return result, fmt.Errorf("JSON parse failed: %w", err)
		}
		result.Findings = findings
		result.ItemCount = len(findings)

	case "line-per-result":
		findings, err := parseLinePerResult(plugin, rawOutput, sessionID)
		if err != nil {
			return result, fmt.Errorf("line-per-result parse failed: %w", err)
		}
		result.Findings = findings
		result.ItemCount = len(findings)

	case "regex":
		findings, err := parseRegex(plugin, rawOutput, sessionID)
		if err != nil {
			return result, fmt.Errorf("regex parse failed: %w", err)
		}
		result.Findings = findings
		result.ItemCount = len(findings)

	default:
		// No parser — return raw output as a single "finding" for logging
		result.Findings = []*types.Finding{{
			ID:         uuid.New().String()[:8],
			State:      types.FindingDetected,
			Title:      fmt.Sprintf("Raw output from %s", plugin.Name),
			DetectedBy: plugin.Name,
			DetectedAt: time.Now(),
			RawOutput:  rawOutput,
			Tags:       []string{"raw", plugin.Category},
		}}
		result.ItemCount = 1
	}

	return result, nil
}

// parseJSON handles JSON output (e.g., nuclei -json, httpx -json)
func parseJSON(plugin *types.PluginDefinition, rawOutput string, sessionID string) ([]*types.Finding, error) {
	var findings []*types.Finding

	// Handle both JSON array and JSONL (one JSON per line) formats
	lines := strings.Split(strings.TrimSpace(rawOutput), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" {
			continue
		}
		line = strings.TrimSuffix(line, ",")

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			continue // Skip non-JSON lines (tool banners, warnings, etc.)
		}

		finding := &types.Finding{
			ID:         uuid.New().String()[:8],
			State:      types.FindingDetected,
			DetectedBy: plugin.Name,
			DetectedAt: time.Now(),
			RawOutput:  line,
			Tags:       []string{plugin.Category},
		}

		// Apply schema mappings from YAML
		for fieldName, schema := range plugin.Parse.Schema {
			value := extractJSONPath(data, schema.Path)
			if value == "" {
				continue
			}
			applyFieldValue(finding, fieldName, value)
		}

		// Fallback: auto-detect common fields from nuclei/httpx output
		if finding.Title == "" {
			if tid, ok := data["template-id"].(string); ok {
				finding.Title = tid
			} else if name, ok := data["name"].(string); ok {
				finding.Title = name
			} else if info, ok := data["info"].(map[string]interface{}); ok {
				if n, ok := info["name"].(string); ok {
					finding.Title = n
				}
			}
		}

		if finding.Severity == "" {
			if sev, ok := data["severity"].(string); ok {
				finding.Severity = sev
			} else if info, ok := data["info"].(map[string]interface{}); ok {
				if s, ok := info["severity"].(string); ok {
					finding.Severity = s
				}
			}
		}

		if finding.URL == "" {
			if host, ok := data["host"].(string); ok {
				finding.URL = host
			} else if url, ok := data["url"].(string); ok {
				finding.URL = url
			} else if matched, ok := data["matched-at"].(string); ok {
				finding.URL = matched
			}
		}

		if finding.VulnType == "" {
			if tags, ok := data["tags"].([]interface{}); ok && len(tags) > 0 {
				if t, ok := tags[0].(string); ok {
					finding.VulnType = t
				}
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// parseLinePerResult handles line-based output (e.g., subfinder, waybackurls)
func parseLinePerResult(plugin *types.PluginDefinition, rawOutput string, sessionID string) ([]*types.Finding, error) {
	var findings []*types.Finding

	lines := strings.Split(strings.TrimSpace(rawOutput), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		finding := &types.Finding{
			ID:         uuid.New().String()[:8],
			State:      types.FindingDetected,
			DetectedBy: plugin.Name,
			DetectedAt: time.Now(),
			Tags:       []string{plugin.Category, plugin.Execute.Output.Type},
		}

		// Apply regex schemas
		for fieldName, schema := range plugin.Parse.Schema {
			if schema.Regex == "" {
				continue
			}
			re, err := regexp.Compile(schema.Regex)
			if err != nil {
				continue
			}
			matches := re.FindStringSubmatch(line)
			if len(matches) > schema.Group {
				applyFieldValue(finding, fieldName, matches[schema.Group])
			}
		}

		// If no schema matched, use the whole line based on output type
		if finding.URL == "" && finding.Target == "" && finding.Title == "" {
			switch plugin.Execute.Output.Type {
			case "subdomains":
				finding.Target = line
				finding.Title = fmt.Sprintf("Subdomain: %s", line)
				finding.VulnType = "subdomain"
			case "urls":
				finding.URL = line
				finding.Title = fmt.Sprintf("URL: %s", line)
				finding.VulnType = "url"
			default:
				finding.Title = line
				finding.RawOutput = line
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// parseRegex handles regex-based parsing
func parseRegex(plugin *types.PluginDefinition, rawOutput string, sessionID string) ([]*types.Finding, error) {
	var findings []*types.Finding

	lines := strings.Split(strings.TrimSpace(rawOutput), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		finding := &types.Finding{
			ID:         uuid.New().String()[:8],
			State:      types.FindingDetected,
			DetectedBy: plugin.Name,
			DetectedAt: time.Now(),
			RawOutput:  line,
			Tags:       []string{plugin.Category},
		}

		matched := false
		for fieldName, schema := range plugin.Parse.Schema {
			if schema.Regex == "" {
				continue
			}
			re, err := regexp.Compile(schema.Regex)
			if err != nil {
				continue
			}
			matches := re.FindStringSubmatch(line)
			if len(matches) > schema.Group {
				applyFieldValue(finding, fieldName, matches[schema.Group])
				matched = true
			}
		}

		if matched {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// extractJSONPath navigates a nested JSON structure using dot-notation path
// e.g., "info.severity" extracts data["info"]["severity"]
func extractJSONPath(data map[string]interface{}, path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return ""
		}
	}

	if current == nil {
		return ""
	}

	switch v := current.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case bool:
		return fmt.Sprintf("%v", v)
	default:
		data, _ := json.Marshal(v)
		return string(data)
	}
}

// applyFieldValue maps a parsed value to the appropriate Finding field
func applyFieldValue(finding *types.Finding, fieldName, value string) {
	switch strings.ToLower(fieldName) {
	case "title", "name", "template_id", "template-id":
		if finding.Title == "" {
			finding.Title = value
		}
	case "severity":
		finding.Severity = value
	case "url", "host", "matched_at", "matched-at":
		finding.URL = value
	case "target", "subdomain", "domain":
		finding.Target = value
	case "vuln_type", "type", "vulnerability_type":
		finding.VulnType = value
	case "description", "desc":
		finding.Description = value
	case "endpoint", "path":
		finding.Endpoint = value
	case "parameter", "param":
		finding.Parameter = value
	case "method":
		finding.Method = value
	case "payload":
		finding.Payload = value
	case "cwe":
		finding.CWE = value
	case "owasp":
		finding.OWASP = value
	case "curl_command", "curl":
		if finding.PoC == nil {
			finding.PoC = &types.PoC{Type: "http"}
		}
		finding.PoC.CurlCommand = value
	}
}

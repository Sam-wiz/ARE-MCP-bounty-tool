// Package core - discovery.go implements JS bundle/config file intelligence gathering.
// Automatically mines endpoints, secrets, and configs from JavaScript files and known config paths.
package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// DiscoveryResult holds results from config/JS analysis
type DiscoveryResult struct {
	Endpoints     []string          `json:"endpoints"`
	Secrets       []SecretMatch     `json:"secrets,omitempty"`
	ConfigValues  map[string]string `json:"config_values,omitempty"`
	JSFiles       []string          `json:"js_files,omitempty"`
	SourceMapURLs []string          `json:"source_map_urls,omitempty"`
}

// SecretMatch represents a detected secret in source code
type SecretMatch struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity"`
}

// Known config file paths to probe
var configPaths = []string{
	"/config.json",
	"/dynamicConfig.json",
	"/settings.json",
	"/env.json",
	"/app-config.json",
	"/runtime-config.js",
	"/api/config",
	"/api/v1/config",
	"/api/settings",
	"/.env",
	"/.env.production",
	"/.env.local",
	"/web.config",
	"/wp-config.php.bak",
	"/config.yml",
	"/config.yaml",
	"/application.yml",
	"/application.properties",
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/swagger/v1/swagger.json",
	"/v2/api-docs",
	"/graphql",
	"/graphql/schema",
	"/.git/config",
	"/.git/HEAD",
	"/robots.txt",
	"/sitemap.xml",
	"/crossdomain.xml",
	"/clientaccesspolicy.xml",
	"/.well-known/security.txt",
	"/.well-known/openid-configuration",
	"/actuator",
	"/actuator/env",
	"/actuator/health",
	"/actuator/info",
	"/debug/vars",
	"/debug/pprof",
	"/server-status",
	"/server-info",
	"/_config.yml",
	"/package.json",
	"/composer.json",
}

// Secret detection patterns
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']`),
	regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(token|access_token|auth_token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{20,})["']`),
	regexp.MustCompile(`(?i)(aws_access_key_id)\s*[:=]\s*["']?(AKIA[0-9A-Z]{16})["']?`),
	regexp.MustCompile(`(?i)(aws_secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
	regexp.MustCompile(`(?i)(firebase[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z_-]{35})["']?`),
	regexp.MustCompile(`(?i)(google[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z_-]{35})["']?`),
	regexp.MustCompile(`(?i)(stripe[_-]?key)\s*[:=]\s*["']?(sk_live_[0-9a-zA-Z]{24,})["']?`),
	regexp.MustCompile(`(?i)(private[_-]?key)\s*[:=]\s*["']([^"']{20,})["']`),
	regexp.MustCompile(`(?i)(slack[_-]?token)\s*[:=]\s*["']?(xox[bpras]-[0-9A-Za-z-]{10,})["']?`),
	regexp.MustCompile(`(?i)(github[_-]?token)\s*[:=]\s*["']?(gh[ps]_[0-9A-Za-z]{36,})["']?`),
	regexp.MustCompile(`(?i)(jwt|bearer)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']?`),
	regexp.MustCompile(`(?i)mongodb(\+srv)?://[^\s"'<]+`),
	regexp.MustCompile(`(?i)postgres://[^\s"'<]+`),
	regexp.MustCompile(`(?i)mysql://[^\s"'<]+`),
	regexp.MustCompile(`(?i)redis://[^\s"'<]+`),
}

// Endpoint patterns to extract from JS
var endpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'](/api/v[0-9]+/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`["'](https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_-]+)["']`),
	regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`axios\.[a-z]+\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`\$\.(?:get|post|ajax|put|delete)\s*\(\s*["']([^"']+)["']`),
	regexp.MustCompile(`url\s*[:=]\s*["']([^"']*api[^"']*)["']`),
	regexp.MustCompile(`endpoint\s*[:=]\s*["']([^"']+)["']`),
	regexp.MustCompile(`path\s*[:=]\s*["'](/[a-zA-Z0-9/_-]+)["']`),
}

// handleDiscoverConfig probes for config files and JS endpoints
func (e *Engine) handleDiscoverConfig(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	baseURL, _ := args["url"].(string)
	if baseURL == "" {
		return errorResult("url is required (base URL of the application)"), nil
	}

	// Trim trailing slash
	baseURL = strings.TrimRight(baseURL, "/")

	mode := "full"
	if m, ok := args["mode"].(string); ok {
		mode = m
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("🔍 Config/JS Discovery: %s (mode: %s)\n\n", baseURL, mode))

	discovery := &DiscoveryResult{
		ConfigValues: make(map[string]string),
	}

	// Phase 1: Probe known config paths
	if mode == "config" || mode == "full" {
		result.WriteString("=== Phase 1: Config File Probing ===\n")
		client := e.newHTTPClient(10 * time.Second)

		for _, path := range configPaths {
			url := baseURL + path
			resp, err := client.Get(url)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 50000))
				resp.Body.Close()

				bodyStr := string(body)

				// Soft 404 Detection: Check if we got HTML for a non-HTML file (e.g. .env, .json)
				// Many SPAs return index.html for unknown routes
				contentType := resp.Header.Get("Content-Type")
				isHTML := strings.Contains(strings.ToLower(contentType), "text/html") ||
					strings.Contains(bodyStr, "<!DOCTYPE") ||
					strings.Contains(bodyStr, "<html") ||
					strings.Contains(bodyStr, "<head")

				// If it's a config file but we got HTML, it's likely a soft 404
				if isHTML && !strings.HasSuffix(path, ".html") && !strings.HasSuffix(path, ".php") && !strings.HasSuffix(path, "/") {
					result.WriteString(fmt.Sprintf("  ⚠️  Soft 404 / HTML Mismatch: %s (ignoring)\n", path))
					continue
				}

				result.WriteString(fmt.Sprintf("  ✅ FOUND: %s (%d bytes)\n", path, len(body)))

				// Check for secrets in the file
				secrets := scanForSecrets(bodyStr, path)
				for _, s := range secrets {
					discovery.Secrets = append(discovery.Secrets, s)
					result.WriteString(fmt.Sprintf("    🔑 SECRET [%s]: %s = %s\n",
						s.Severity, s.Type, truncateString(s.Value, 40)))
				}

				// Try to extract endpoints
				endpoints := extractEndpoints(bodyStr)
				discovery.Endpoints = append(discovery.Endpoints, endpoints...)
			} else {
				resp.Body.Close()
			}
		}
		result.WriteString(fmt.Sprintf("\n  Config files checked: %d\n\n", len(configPaths)))
	}

	// Phase 2: Fetch and analyze JS files
	if mode == "js" || mode == "full" {
		result.WriteString("=== Phase 2: JavaScript Analysis ===\n")

		// First, get the main page and find JS files (egress via proxy)
		jsFiles := findJSFiles(ctx, e.newHTTPClient(15*time.Second), baseURL)
		discovery.JSFiles = jsFiles
		result.WriteString(fmt.Sprintf("  Found %d JS files\n", len(jsFiles)))

		// Analyze each JS file
		client := e.newHTTPClient(15 * time.Second)
		for _, jsURL := range jsFiles {
			if !strings.HasPrefix(jsURL, "http") {
				jsURL = baseURL + jsURL
			}

			resp, err := client.Get(jsURL)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 500000)) // 500KB limit per file
			resp.Body.Close()

			jsContent := string(body)

			// Check for source maps
			if strings.Contains(jsContent, "sourceMappingURL") {
				re := regexp.MustCompile(`//# sourceMappingURL=(.+)`)
				if m := re.FindStringSubmatch(jsContent); len(m) > 1 {
					discovery.SourceMapURLs = append(discovery.SourceMapURLs, m[1])
					result.WriteString(fmt.Sprintf("  📍 Source map: %s → %s\n", jsURL, m[1]))
				}
			}

			// Extract secrets
			secrets := scanForSecrets(jsContent, jsURL)
			for _, s := range secrets {
				discovery.Secrets = append(discovery.Secrets, s)
				result.WriteString(fmt.Sprintf("  🔑 SECRET in %s: [%s] %s\n",
					jsURL, s.Type, truncateString(s.Value, 50)))
			}

			// Extract endpoints
			endpoints := extractEndpoints(jsContent)
			discovery.Endpoints = append(discovery.Endpoints, endpoints...)
		}
	}

	// Deduplicate endpoints
	discovery.Endpoints = dedup(discovery.Endpoints)

	// Summary
	result.WriteString(fmt.Sprintf("\n=== Summary ===\n"))
	result.WriteString(fmt.Sprintf("Endpoints found: %d\n", len(discovery.Endpoints)))
	result.WriteString(fmt.Sprintf("Secrets found: %d\n", len(discovery.Secrets)))
	result.WriteString(fmt.Sprintf("JS files: %d\n", len(discovery.JSFiles)))
	result.WriteString(fmt.Sprintf("Source maps: %d\n", len(discovery.SourceMapURLs)))

	if len(discovery.Endpoints) > 0 {
		result.WriteString("\n--- Discovered Endpoints ---\n")
		limit := 50
		if len(discovery.Endpoints) < limit {
			limit = len(discovery.Endpoints)
		}
		for i := 0; i < limit; i++ {
			result.WriteString(fmt.Sprintf("  %s\n", discovery.Endpoints[i]))
		}
		if len(discovery.Endpoints) > limit {
			result.WriteString(fmt.Sprintf("  ... and %d more\n", len(discovery.Endpoints)-limit))
		}
	}

	// Auto-ingest secrets as findings
	for _, s := range discovery.Secrets {
		finding := &types.Finding{
			ID:          uuid.New().String()[:8],
			State:       types.FindingDetected,
			Title:       fmt.Sprintf("Exposed %s in %s", s.Type, s.File),
			Severity:    s.Severity,
			VulnType:    "information-disclosure",
			URL:         baseURL,
			Target:      baseURL,
			DetectedBy:  "discovery",
			DetectedAt:  time.Now(),
			CWE:         "CWE-200",
			OWASP:       "A01:2021",
			Tags:        []string{"secret", "config", s.Type},
			RawOutput:   s.Value,
		}
		e.mu.Lock()
		e.findings[finding.ID] = finding
		e.mu.Unlock()
		if e.config.MongoDB != nil {
			e.config.MongoDB.SaveFinding(ctx, finding)
		}
	}

	return successResult(result.String()), nil
}

// findJSFiles fetches the page HTML and extracts JS file URLs (via the
// supplied client, which carries any egress proxy).
func findJSFiles(ctx context.Context, client *http.Client, baseURL string) []string {
	resp, err := client.Get(baseURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500000))
	html := string(body)

	jsRegex := regexp.MustCompile(`(?:src|href)\s*=\s*["']([^"']*\.js)["']`)
	matches := jsRegex.FindAllStringSubmatch(html, -1)

	var jsFiles []string
	for _, m := range matches {
		if len(m) > 1 {
			jsFiles = append(jsFiles, m[1])
		}
	}
	return dedup(jsFiles)
}

// scanForSecrets scans content for known secret patterns
func scanForSecrets(content, filename string) []SecretMatch {
	var secrets []SecretMatch
	seenValues := map[string]bool{}

	for _, pattern := range secretPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			value := ""
			secretType := "unknown"

			if len(m) > 2 {
				secretType = m[1]
				value = m[2]
			} else if len(m) > 1 {
				value = m[1]
			}

			// Deduplication and length check
			if seenValues[value] || len(value) < 8 {
				continue
			}
			
			// False Positive Filtering
			// 1. Ignore if value is all uppercase (likely a constant like INVALID_PASSWORD)
			isAllUpper := true
			for _, r := range value {
				if r >= 'a' && r <= 'z' {
					isAllUpper = false
					break
				}
			}
			if isAllUpper {
				continue
			}

			// 2. Ignore specific false positive prefixes/substrings
			upperVal := strings.ToUpper(value)
			if strings.HasPrefix(upperVal, "INVALID_") || 
			   strings.HasPrefix(upperVal, "ERROR_") ||
			   strings.Contains(upperVal, "PLACEHOLDER") ||
			   strings.Contains(upperVal, "EXAMPLE") ||
			   strings.Contains(upperVal, "ERROR") ||
			   strings.Contains(upperVal, "STATE") ||
			   strings.Contains(upperVal, "FORM") ||
			   strings.Contains(upperVal, "MESSAGE") ||
			   strings.Contains(upperVal, "UPDATED") ||
			   strings.Contains(upperVal, "RESET") ||
			   strings.Contains(upperVal, "BUTTON") ||
			   strings.Contains(upperVal, "LABEL") {
				continue
			}

			// 3. Ignore if value is same as key (e.g. password = "password")
			if strings.EqualFold(secretType, value) {
				continue
			}

			seenValues[value] = true

			severity := "medium"
			valueLower := strings.ToLower(value)
			typeLower := strings.ToLower(secretType)
			if strings.Contains(typeLower, "aws") || strings.Contains(typeLower, "private") ||
				strings.Contains(valueLower, "sk_live") || strings.Contains(typeLower, "password") {
				severity = "critical"
			} else if strings.Contains(typeLower, "api_key") || strings.Contains(typeLower, "token") {
				severity = "high"
			}

			secrets = append(secrets, SecretMatch{
				Type:     secretType,
				Value:    value,
				File:     filename,
				Severity: severity,
			})
		}
	}
	return secrets
}

// extractEndpoints extracts API endpoints from content
func extractEndpoints(content string) []string {
	var endpoints []string
	seen := map[string]bool{}

	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 1 {
				ep := m[1]
				// Filter out obvious non-endpoints
				if len(ep) < 2 || strings.HasSuffix(ep, ".css") || strings.HasSuffix(ep, ".png") ||
					strings.HasSuffix(ep, ".jpg") || strings.HasSuffix(ep, ".svg") ||
					strings.HasSuffix(ep, ".ico") || strings.HasSuffix(ep, ".woff") {
					continue
				}
				if !seen[ep] {
					seen[ep] = true
					endpoints = append(endpoints, ep)
				}
			}
		}
	}
	return endpoints
}

// dedup removes duplicates from a string slice
func dedup(items []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

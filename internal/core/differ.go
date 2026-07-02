// Package core - differ.go implements response comparison / differential analysis.
// Critical for IDOR detection: proves that different user contexts return different data.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// DiffResult holds the result of comparing two API responses
type DiffResult struct {
	URL1         string            `json:"url1"`
	URL2         string            `json:"url2"`
	Method       string            `json:"method"`
	StatusCode1  int               `json:"status_code_1"`
	StatusCode2  int               `json:"status_code_2"`
	BodyMatch    bool              `json:"body_match"`
	HeaderDiffs  []HeaderDiff      `json:"header_diffs,omitempty"`
	JSONDiffs    []JSONDiff        `json:"json_diffs,omitempty"`
	TextDiffs    []TextDiff        `json:"text_diffs,omitempty"`
	DataLeaked   bool              `json:"data_leaked"`
	LeakedFields []string          `json:"leaked_fields,omitempty"`
	Severity     string            `json:"severity"`
	Summary      string            `json:"summary"`
}

// HeaderDiff represents a difference in response headers
type HeaderDiff struct {
	Name   string `json:"name"`
	Value1 string `json:"value1"`
	Value2 string `json:"value2"`
}

// JSONDiff represents a difference in JSON response bodies
type JSONDiff struct {
	Path   string `json:"path"`
	Value1 interface{} `json:"value1,omitempty"`
	Value2 interface{} `json:"value2,omitempty"`
	Type   string `json:"type"` // "added", "removed", "changed", "type_changed"
}

// TextDiff represents a line-level diff for non-JSON responses
type TextDiff struct {
	Line    int    `json:"line"`
	Type    string `json:"type"` // "added", "removed", "changed"
	Content string `json:"content"`
}

// ResponseCapture holds a captured HTTP response
type ResponseCapture struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	BodySize   int               `json:"body_size"`
	Duration   time.Duration     `json:"duration"`
}

// CompareResponses performs a full differential analysis between two URLs
func (e *Engine) CompareResponses(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	url1, _ := args["url1"].(string)
	url2, _ := args["url2"].(string)
	if url1 == "" || url2 == "" {
		return errorResult("url1 and url2 are required"), nil
	}

	// Scope enforcement on both targets.
	if err := e.validateURLScope(url1); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := e.validateURLScope(url2); err != nil {
		return errorResult(err.Error()), nil
	}

	method := "GET"
	if m, ok := args["method"].(string); ok {
		method = strings.ToUpper(m)
	}

	// Build headers
	headers := map[string]string{}
	if h, ok := args["headers"].(map[string]interface{}); ok {
		for k, v := range h {
			headers[k] = fmt.Sprintf("%v", v)
		}
	}

	// Auth tokens for each request
	auth1, _ := args["auth1"].(string)
	auth2, _ := args["auth2"].(string)

	body, _ := args["body"].(string)

	// Capture both responses (egress through the configured proxy)
	client := e.newHTTPClient(30 * time.Second)
	resp1, err := captureResponse(ctx, client, method, url1, headers, auth1, body)
	if err != nil {
		return errorResult(fmt.Sprintf("Request 1 failed: %v", err)), nil
	}

	resp2, err := captureResponse(ctx, client, method, url2, headers, auth2, body)
	if err != nil {
		return errorResult(fmt.Sprintf("Request 2 failed: %v", err)), nil
	}

	// Perform differential analysis
	diff := performDiff(url1, url2, method, resp1, resp2)

	// Build result
	var result strings.Builder
	result.WriteString(fmt.Sprintf("🔍 Differential Analysis: %s\n\n", method))
	result.WriteString(fmt.Sprintf("URL 1: %s → %d (%d bytes)\n", url1, diff.StatusCode1, resp1.BodySize))
	result.WriteString(fmt.Sprintf("URL 2: %s → %d (%d bytes)\n\n", url2, diff.StatusCode2, resp2.BodySize))

	if diff.BodyMatch {
		result.WriteString("⚠️  Bodies are IDENTICAL — may be a generic/template response\n")
	} else {
		result.WriteString("🔴 Bodies DIFFER — potential data exposure confirmed!\n\n")

		if len(diff.JSONDiffs) > 0 {
			result.WriteString("--- JSON Differences ---\n")
			for _, d := range diff.JSONDiffs {
				switch d.Type {
				case "changed":
					result.WriteString(fmt.Sprintf("  CHANGED %s: %v → %v\n", d.Path, d.Value1, d.Value2))
				case "added":
					result.WriteString(fmt.Sprintf("  ADDED   %s: %v\n", d.Path, d.Value2))
				case "removed":
					result.WriteString(fmt.Sprintf("  REMOVED %s: %v\n", d.Path, d.Value1))
				}
			}
		}

		if len(diff.TextDiffs) > 0 {
			result.WriteString("--- Text Differences ---\n")
			limit := 20
			if len(diff.TextDiffs) < limit {
				limit = len(diff.TextDiffs)
			}
			for i := 0; i < limit; i++ {
				d := diff.TextDiffs[i]
				result.WriteString(fmt.Sprintf("  [%s] L%d: %s\n", d.Type, d.Line, truncateString(d.Content, 120)))
			}
			if len(diff.TextDiffs) > limit {
				result.WriteString(fmt.Sprintf("  ... and %d more differences\n", len(diff.TextDiffs)-limit))
			}
		}
	}

	if diff.DataLeaked {
		result.WriteString(fmt.Sprintf("\n🔴 DATA LEAK DETECTED: %v\n", diff.LeakedFields))
		result.WriteString(fmt.Sprintf("Severity: %s\n", diff.Severity))
	}

	if len(diff.HeaderDiffs) > 0 {
		result.WriteString("\n--- Header Differences ---\n")
		for _, h := range diff.HeaderDiffs {
			result.WriteString(fmt.Sprintf("  %s: %q vs %q\n", h.Name, h.Value1, h.Value2))
		}
	}

	result.WriteString(fmt.Sprintf("\n📋 Summary: %s\n", diff.Summary))

	// Auto-ingest as finding if data leaked
	if diff.DataLeaked {
		finding := &types.Finding{
			ID:          uuid.New().String()[:8],
			State:       types.FindingDetected,
			Title:       fmt.Sprintf("IDOR: Differential data exposure on %s", url1),
			Description: diff.Summary,
			Severity:    diff.Severity,
			VulnType:    "idor",
			URL:         url1,
			Method:      method,
			DetectedBy:  "differ",
			DetectedAt:  time.Now(),
			OWASP:       "A01:2021",
			CWE:         "CWE-639",
			Tags:        []string{"idor", "differential", "data-leak"},
		}
		e.mu.Lock()
		e.findings[finding.ID] = finding
		e.mu.Unlock()

		if e.config.MongoDB != nil {
			e.config.MongoDB.SaveFinding(ctx, finding)
		}
		result.WriteString(fmt.Sprintf("\n📦 Auto-ingested as finding %s\n", finding.ID))
	}

	return successResult(result.String()), nil
}

// captureResponse performs an HTTP request and captures the full response,
// using the supplied client (which carries any egress proxy).
func captureResponse(ctx context.Context, client *http.Client, method, url string, headers map[string]string, auth string, body string) (*ResponseCapture, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, err
	}

	capture := &ResponseCapture{
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
		Body:       string(respBody),
		BodySize:   len(respBody),
		Duration:   time.Since(start),
	}

	for k := range resp.Header {
		capture.Headers[k] = resp.Header.Get(k)
	}

	return capture, nil
}

// performDiff compares two captured responses
func performDiff(url1, url2, method string, resp1, resp2 *ResponseCapture) *DiffResult {
	diff := &DiffResult{
		URL1:        url1,
		URL2:        url2,
		Method:      method,
		StatusCode1: resp1.StatusCode,
		StatusCode2: resp2.StatusCode,
		BodyMatch:   resp1.Body == resp2.Body,
	}

	// Compare headers
	allHeaders := map[string]bool{}
	for k := range resp1.Headers {
		allHeaders[k] = true
	}
	for k := range resp2.Headers {
		allHeaders[k] = true
	}

	for h := range allHeaders {
		v1 := resp1.Headers[h]
		v2 := resp2.Headers[h]
		if v1 != v2 {
			// Skip dynamic headers
			if h == "Date" || h == "X-Request-Id" || h == "Set-Cookie" {
				continue
			}
			diff.HeaderDiffs = append(diff.HeaderDiffs, HeaderDiff{Name: h, Value1: v1, Value2: v2})
		}
	}

	// Compare bodies
	if !diff.BodyMatch {
		// Try JSON diff first
		var json1, json2 interface{}
		isJSON1 := json.Unmarshal([]byte(resp1.Body), &json1) == nil
		isJSON2 := json.Unmarshal([]byte(resp2.Body), &json2) == nil

		if isJSON1 && isJSON2 {
			diff.JSONDiffs = compareJSON("$", json1, json2)
			// Check for PII/sensitive data in diffs
			diff.LeakedFields, diff.DataLeaked = detectDataLeak(diff.JSONDiffs)
		} else {
			// Text diff
			diff.TextDiffs = compareText(resp1.Body, resp2.Body)
		}
	}

	// Determine severity
	if diff.DataLeaked {
		if containsSensitiveField(diff.LeakedFields) {
			diff.Severity = "high"
		} else {
			diff.Severity = "medium"
		}
	} else if !diff.BodyMatch {
		diff.Severity = "low"
	} else {
		diff.Severity = "info"
	}

	// Build summary
	if diff.BodyMatch {
		diff.Summary = "Responses are identical — no differential data exposure"
	} else if diff.DataLeaked {
		diff.Summary = fmt.Sprintf("IDOR confirmed: %d fields with user-specific data leaked (%s)",
			len(diff.LeakedFields), strings.Join(diff.LeakedFields, ", "))
	} else {
		diff.Summary = fmt.Sprintf("Responses differ (%d JSON diffs, %d text diffs) but no clear PII leak detected",
			len(diff.JSONDiffs), len(diff.TextDiffs))
	}

	return diff
}

// compareJSON recursively compares two JSON values and returns differences
func compareJSON(path string, v1, v2 interface{}) []JSONDiff {
	var diffs []JSONDiff

	switch a := v1.(type) {
	case map[string]interface{}:
		b, ok := v2.(map[string]interface{})
		if !ok {
			return append(diffs, JSONDiff{Path: path, Value1: v1, Value2: v2, Type: "type_changed"})
		}
		// Check all keys
		allKeys := map[string]bool{}
		for k := range a {
			allKeys[k] = true
		}
		for k := range b {
			allKeys[k] = true
		}

		keys := make([]string, 0, len(allKeys))
		for k := range allKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			childPath := path + "." + k
			va, hasA := a[k]
			vb, hasB := b[k]

			if hasA && !hasB {
				diffs = append(diffs, JSONDiff{Path: childPath, Value1: va, Type: "removed"})
			} else if !hasA && hasB {
				diffs = append(diffs, JSONDiff{Path: childPath, Value2: vb, Type: "added"})
			} else {
				diffs = append(diffs, compareJSON(childPath, va, vb)...)
			}
		}

	case []interface{}:
		b, ok := v2.([]interface{})
		if !ok {
			return append(diffs, JSONDiff{Path: path, Value1: v1, Value2: v2, Type: "type_changed"})
		}

		maxLen := len(a)
		if len(b) > maxLen {
			maxLen = len(b)
		}
		for i := 0; i < maxLen; i++ {
			indexPath := fmt.Sprintf("%s[%d]", path, i)
			if i >= len(a) {
				diffs = append(diffs, JSONDiff{Path: indexPath, Value2: b[i], Type: "added"})
			} else if i >= len(b) {
				diffs = append(diffs, JSONDiff{Path: indexPath, Value1: a[i], Type: "removed"})
			} else {
				diffs = append(diffs, compareJSON(indexPath, a[i], b[i])...)
			}
		}

	default:
		// Primitive comparison
		if fmt.Sprintf("%v", v1) != fmt.Sprintf("%v", v2) {
			diffs = append(diffs, JSONDiff{Path: path, Value1: v1, Value2: v2, Type: "changed"})
		}
	}

	return diffs
}

// compareText does a simple line-by-line diff
func compareText(text1, text2 string) []TextDiff {
	lines1 := strings.Split(text1, "\n")
	lines2 := strings.Split(text2, "\n")
	var diffs []TextDiff

	maxLen := len(lines1)
	if len(lines2) > maxLen {
		maxLen = len(lines2)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(lines1) {
			diffs = append(diffs, TextDiff{Line: i + 1, Type: "added", Content: lines2[i]})
		} else if i >= len(lines2) {
			diffs = append(diffs, TextDiff{Line: i + 1, Type: "removed", Content: lines1[i]})
		} else if lines1[i] != lines2[i] {
			diffs = append(diffs, TextDiff{Line: i + 1, Type: "changed", Content: lines2[i]})
		}
	}

	return diffs
}

// sensitivePatterns are field names that indicate PII or sensitive data
var sensitivePatterns = []string{
	"email", "mail", "phone", "mobile", "address", "name", "first_name", "last_name",
	"username", "user_name", "user_id", "userId", "account", "balance", "credit",
	"password", "secret", "token", "ssn", "dob", "date_of_birth", "birth",
	"card", "payment", "billing", "salary", "income", "score", "points",
	"dashpoints", "coins", "gems", "currency", "wallet",
}

// detectDataLeak checks JSON diffs for sensitive field names
func detectDataLeak(diffs []JSONDiff) ([]string, bool) {
	leaked := []string{}
	seen := map[string]bool{}

	for _, d := range diffs {
		if d.Type == "changed" || d.Type == "added" {
			pathLower := strings.ToLower(d.Path)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(pathLower, pattern) && !seen[pattern] {
					leaked = append(leaked, d.Path)
					seen[pattern] = true
					break
				}
			}
		}
	}

	return leaked, len(leaked) > 0
}

// containsSensitiveField checks if any leaked fields are high-severity
func containsSensitiveField(fields []string) bool {
	highSeverity := []string{"password", "secret", "token", "ssn", "card", "payment", "balance", "salary"}
	for _, f := range fields {
		fLower := strings.ToLower(f)
		for _, s := range highSeverity {
			if strings.Contains(fLower, s) {
				return true
			}
		}
	}
	return false
}

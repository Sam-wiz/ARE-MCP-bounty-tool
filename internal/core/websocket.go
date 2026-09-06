// Package core - websocket.go implements WebSocket and STOMP protocol testing.
// Tests for common WebSocket vulnerabilities: auth bypass, injection, DoS, CSWSH.
package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// handleTestWebSocket performs WebSocket/STOMP security testing
func (e *Engine) handleTestWebSocket(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	wsURL, _ := args["url"].(string)
	if wsURL == "" {
		return errorResult("url is required (ws:// or wss:// URL)"), nil
	}

	// Normalize URL
	if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + wsURL[7:]
	} else if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + wsURL[8:]
	} else if !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://") {
		wsURL = "wss://" + wsURL
	}

	protocol := "raw"
	if p, ok := args["protocol"].(string); ok {
		protocol = p
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("🔌 WebSocket Testing: %s (protocol: %s)\n\n", wsURL, protocol))

	// Test 1: Basic connectivity using websocat
	results.WriteString("=== Test 1: Connectivity ===\n")
	connectResult, _ := e.ExecuteRawCommand(ctx,
		fmt.Sprintf("echo 'test' | timeout 5 websocat -1 %s 2>&1 || echo 'Connection failed or websocat not installed'", ShellEscape(wsURL)),
		"ws-connect", 10)
	results.WriteString(connectResult.Content[0].Text)
	results.WriteString("\n")

	// Test 2: Cross-Site WebSocket Hijacking (CSWSH)
	results.WriteString("\n=== Test 2: CSWSH Check ===\n")
	// Test with different Origin headers
	origins := []string{
		"https://evil.com",
		"https://attacker.com",
		"null",
	}
	for _, origin := range origins {
		cswshResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("echo 'test' | timeout 5 websocat --origin %s -1 %s 2>&1 || echo 'Rejected'", ShellEscape(origin), ShellEscape(wsURL)),
			"ws-cswsh", 10)
		output := cswshResult.Content[0].Text
		if !strings.Contains(output, "Rejected") && !strings.Contains(output, "403") &&
			!strings.Contains(output, "failed") && !strings.Contains(output, "error") {
			results.WriteString(fmt.Sprintf("  🔴 VULNERABLE: Origin '%s' accepted!\n", origin))

			// Auto-ingest CSWSH finding
			finding := &types.Finding{
				ID:          uuid.New().String()[:8],
				State:       types.FindingDetected,
				Title:       fmt.Sprintf("Cross-Site WebSocket Hijacking on %s", wsURL),
				Description: fmt.Sprintf("WebSocket endpoint accepts connections from arbitrary origin: %s", origin),
				Severity:    "high",
				VulnType:    "cswsh",
				URL:         wsURL,
				DetectedBy:  "websocket-test",
				DetectedAt:  time.Now(),
				CWE:         "CWE-1385",
				OWASP:       "A01:2021",
				Tags:        []string{"websocket", "cswsh", "origin-check"},
			}
			e.mu.Lock()
			e.findings[finding.ID] = finding
			e.mu.Unlock()
			if e.config.MongoDB != nil {
				e.config.MongoDB.SaveFinding(ctx, finding)
			}
			results.WriteString(fmt.Sprintf("  📦 Finding ingested: %s\n", finding.ID))
		} else {
			results.WriteString(fmt.Sprintf("  ✅ Origin '%s' correctly rejected\n", origin))
		}
	}

	// Test 3: Auth bypass — connect without token
	results.WriteString("\n=== Test 3: Auth Bypass ===\n")
	if token, ok := args["token"].(string); ok && token != "" {
		// Test with token
		results.WriteString("  Testing with token...\n")
		authResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("echo 'test' | timeout 5 websocat -H %s -1 %s 2>&1", ShellEscape("Authorization: Bearer "+token), ShellEscape(wsURL)),
			"ws-auth", 10)
		results.WriteString(fmt.Sprintf("  With token: %s\n", truncateString(authResult.Content[0].Text, 200)))

		// Test without token
		results.WriteString("  Testing without token...\n")
		noAuthResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("echo 'test' | timeout 5 websocat -1 %s 2>&1", ShellEscape(wsURL)),
			"ws-noauth", 10)
		results.WriteString(fmt.Sprintf("  No token: %s\n", truncateString(noAuthResult.Content[0].Text, 200)))
	}

	// Test 4: STOMP-specific tests
	if protocol == "stomp" {
		results.WriteString("\n=== Test 4: STOMP Protocol Tests ===\n")

		// STOMP CONNECT frame
		stompConnect := `CONNECT\naccept-version:1.2\nhost:` + wsURL + `\n\n\x00`
		stompResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("printf %s | timeout 5 websocat -1 %s 2>&1", ShellEscape(stompConnect), ShellEscape(wsURL)),
			"stomp-connect", 10)
		results.WriteString(fmt.Sprintf("  STOMP CONNECT: %s\n", truncateString(stompResult.Content[0].Text, 200)))

		// Try subscribing to common topics
		topics := []string{
			"/topic/notifications",
			"/topic/messages",
			"/queue/admin",
			"/user/queue/private",
			"/app/admin",
		}
		for _, topic := range topics {
			stompSub := fmt.Sprintf(`SUBSCRIBE\nid:sub-0\ndestination:%s\n\n\x00`, topic)
			subResult, _ := e.ExecuteRawCommand(ctx,
				fmt.Sprintf("printf %s | timeout 5 websocat -1 %s 2>&1", ShellEscape(stompSub), ShellEscape(wsURL)),
				"stomp-subscribe", 10)
			output := subResult.Content[0].Text
			if !strings.Contains(output, "error") && !strings.Contains(output, "ERROR") &&
				output != "" && !strings.Contains(output, "failed") {
				results.WriteString(fmt.Sprintf("  🔴 Topic accessible: %s\n", topic))
			} else {
				results.WriteString(fmt.Sprintf("  ✅ Topic blocked: %s\n", topic))
			}
		}
	}

	// Test 5: Injection tests
	results.WriteString("\n=== Test 5: Injection Tests ===\n")
	injectionPayloads := []string{
		`<script>alert(1)</script>`,
		`{"__proto__":{"polluted":true}}`,
		`' OR '1'='1`,
		`{{7*7}}`,
		`${7*7}`,
	}
	for _, payload := range injectionPayloads {
		injectResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("echo %s | timeout 5 websocat -1 %s 2>&1",
				ShellEscape(payload), ShellEscape(wsURL)),
			"ws-inject", 10)
		output := injectResult.Content[0].Text
		if strings.Contains(output, "alert") || strings.Contains(output, "49") ||
			strings.Contains(output, "polluted") {
			results.WriteString(fmt.Sprintf("  🔴 Payload reflected: %s\n", payload))
		} else {
			results.WriteString(fmt.Sprintf("  ✅ Payload: %s → filtered/ignored\n", truncateString(payload, 40)))
		}
	}

	return successResult(results.String()), nil
}

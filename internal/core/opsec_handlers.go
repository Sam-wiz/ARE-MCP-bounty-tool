package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// OPSEC HANDLERS
// ============================================================================

func (e *Engine) handleOpsecSetup(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	var results strings.Builder
	results.WriteString("🛡️ OPSEC Setup\n\n")

	// Egress proxy — the knob that unblocks geo-restricted targets. Accepts
	// http://, https://, socks5://[user:pass@]host:port. Once set, ALL request
	// tools (http_request, api_test, compare_responses, discover_config) leave
	// from this proxy's IP.
	if proxy, ok := args["proxy"].(string); ok && proxy != "" {
		e.setEgressProxy(proxy)
		results.WriteString("=== Egress Proxy ===\n")
		results.WriteString(fmt.Sprintf("Configured: %s\n", redactProxy(proxy)))
		ipRes, _ := e.ExecuteRawCommand(ctx,
			"curl -s"+e.curlProxyArg()+" --max-time 15 https://ifconfig.me 2>/dev/null || echo '(proxy unreachable)'",
			"ip-check", 20)
		results.WriteString(fmt.Sprintf("Egress IP now: %s\n", strings.TrimSpace(ipRes.Content[0].Text)))
		results.WriteString("All request tools now egress through this proxy.\n\n")
	}

	// MAC spoofing
	if macSpoof, ok := args["mac_spoof"].(bool); ok && macSpoof {
		results.WriteString("=== MAC Spoofing ===\n")
		result, _ := e.ExecuteRawCommand(ctx,
			"ifconfig en0 | grep ether",
			"mac-check", 5)
		results.WriteString(fmt.Sprintf("Current MAC: %s\n", result.Content[0].Text))
		results.WriteString("⚠️  To spoof: sudo ifconfig en0 ether XX:XX:XX:XX:XX:XX\n\n")
	}

	// Tor check
	if useTor, ok := args["tor"].(bool); ok && useTor {
		results.WriteString("=== Tor Setup ===\n")
		result, _ := e.ExecuteRawCommand(ctx,
			"which tor && tor --version 2>/dev/null | head -1 || echo 'Tor not installed (brew install tor)'",
			"tor-check", 5)
		results.WriteString(result.Content[0].Text)
		results.WriteString("\n\n")
	}

	// VPN check
	if vpnConfig, ok := args["vpn"].(string); ok && vpnConfig != "" {
		results.WriteString("=== VPN Setup ===\n")
		results.WriteString(fmt.Sprintf("Config: %s\n", vpnConfig))
		result, _ := e.ExecuteRawCommand(ctx,
			"curl -s ifconfig.me 2>/dev/null",
			"ip-check", 10)
		results.WriteString(fmt.Sprintf("Current IP: %s\n", result.Content[0].Text))
	}

	return successResult(results.String()), nil
}

func (e *Engine) handleOpsecVerify(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	var results strings.Builder
	results.WriteString("🛡️ OPSEC Verification\n\n")

	// IP check — through the egress proxy the request tools actually use.
	results.WriteString("=== Egress IP Address ===\n")
	results.WriteString(fmt.Sprintf("Egress path: %s\n", e.egressLabel()))
	ipResult, _ := e.ExecuteRawCommand(ctx, "curl -s"+e.curlProxyArg()+" --max-time 15 ifconfig.me 2>/dev/null", "ip-check", 20)
	results.WriteString(ipResult.Content[0].Text)

	// DNS leak check
	results.WriteString("\n\n=== DNS Resolver ===\n")
	dnsResult, _ := e.ExecuteRawCommand(ctx,
		"dig +short whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null || nslookup -type=txt o-o.myaddr.l.google.com ns1.google.com 2>/dev/null | tail -2",
		"dns-check", 10)
	results.WriteString(dnsResult.Content[0].Text)

	// Tor check
	results.WriteString("\n\n=== Tor Status ===\n")
	torResult, _ := e.ExecuteRawCommand(ctx,
		"curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip 2>/dev/null || echo 'Tor not running'",
		"tor-check", 10)
	results.WriteString(torResult.Content[0].Text)

	return successResult(results.String()), nil
}

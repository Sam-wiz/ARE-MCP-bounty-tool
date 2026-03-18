package mcp

import (
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// registerTools registers all available MCP tools
func (s *Server) registerTools() {
	s.tools = []types.ToolDefinition{
		// === SCOPE & CONFIGURATION ===
		{
			Name:        "set_target",
			Description: "Set target domain and define authorized scope for testing",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Primary target domain",
					},
					"in_scope": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "In-scope patterns (e.g., *.example.com)",
					},
					"out_of_scope": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Out-of-scope patterns",
					},
				},
				"required": []string{"domain"},
			},
		},
		{
			Name:        "validate_scope",
			Description: "Validate if a target is within authorized scope",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Target URL or domain to validate",
					},
				},
				"required": []string{"target"},
			},
		},

		// === RECONNAISSANCE ===
		{
			Name:        "recon_discover",
			Description: "Complete reconnaissance: subdomain discovery → HTTP probing → endpoint discovery. Uses: subfinder, amass, httpx, katana, waybackurls",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Target domain",
					},
					"mode": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"passive", "active", "deep"},
						"description": "Recon depth: passive (safe), active (DNS brute), deep (comprehensive)",
					},
					"concurrency": map[string]interface{}{
						"type":        "number",
						"description": "Concurrency level (default: 5)",
					},
				},
				"required": []string{"domain"},
			},
		},

		// === VULNERABILITY SCANNING ===
		{
			Name:        "scan_vulnerabilities",
			Description: "Comprehensive vulnerability scanning with nuclei (5000+ templates) and nikto. Findings go through validation pipeline.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"targets": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Target URLs to scan",
					},
					"severity": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Severity filter: critical, high, medium, low",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Nuclei tags: xss, sqli, rce, ssrf, etc.",
					},
					"validate": map[string]interface{}{
						"type":        "boolean",
						"description": "Run validation pipeline (default: true)",
					},
				},
				"required": []string{"targets"},
			},
		},

		// === INJECTION TESTING ===
		{
			Name:        "test_injection",
			Description: "Test for injection vulnerabilities (XSS, SQLi, SSTI, XXE). Includes PoC generation and verification.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"urls": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "URLs with parameters to test",
					},
					"types": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Injection types: xss, sqli, ssti, xxe, cmdi",
					},
					"mode": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"quick", "deep"},
						"description": "Test depth",
					},
				},
				"required": []string{"urls"},
			},
		},

		// === CLOUD TESTING ===
		{
			Name:        "test_cloud",
			Description: "Cloud security testing for AWS, GCP, Azure. Checks misconfigurations, IAM, S3 buckets, etc.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"provider": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"aws", "gcp", "azure", "auto"},
						"description": "Cloud provider to test",
					},
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Target (domain, bucket name, etc.)",
					},
					"checks": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Specific checks: s3, iam, ec2, lambda, etc.",
					},
				},
				"required": []string{"target"},
			},
		},

		// === MOBILE TESTING ===
		{
			Name:        "test_mobile",
			Description: "Mobile app security testing with Frida, APKTool, ADB. Controls emulator for dynamic analysis.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"apk_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to APK file (for Android)",
					},
					"package_name": map[string]interface{}{
						"type":        "string",
						"description": "Package name if already installed",
					},
					"mode": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"static", "dynamic", "full"},
						"description": "Analysis mode",
					},
					"frida_script": map[string]interface{}{
						"type":        "string",
						"description": "Custom Frida script to run",
					},
				},
			},
		},

		// === APP DOWNLOAD ===
		{
			Name:        "download_app",
			Description: "Download APK from Google Play or APKPure (no auth needed for APKPure), or IPA from the Apple App Store. Use before test_mobile to pull the app directly.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"platform": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"android", "ios"},
						"description": "Target platform",
					},
					"package_id": map[string]interface{}{
						"type":        "string",
						"description": "Android package name (com.example.app) or iOS bundle ID",
					},
					"source": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"apkpure", "google-play"},
						"description": "Android only — apkpure (no auth) or google-play (needs credentials)",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory to save the downloaded file (default: /tmp/apks)",
					},
					"email": map[string]interface{}{
						"type":        "string",
						"description": "Google account email (google-play source) or Apple ID (iOS)",
					},
					"password": map[string]interface{}{
						"type":        "string",
						"description": "Google account password or Apple ID password",
					},
				},
				"required": []string{"platform", "package_id"},
			},
		},

		// === FUZZING ===
		{
			Name:        "fuzz_target",
			Description: "Start autonomous fuzzing job. Runs in background and reports crashes/findings.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Target to fuzz (URL, binary path)",
					},
					"type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"http", "binary", "api"},
						"description": "Fuzzing type",
					},
					"duration": map[string]interface{}{
						"type":        "number",
						"description": "Duration in minutes (0 = until stopped)",
					},
					"wordlist": map[string]interface{}{
						"type":        "string",
						"description": "Custom wordlist path",
					},
				},
				"required": []string{"target", "type"},
			},
		},

		// === VALIDATION ===
		{
			Name:        "validate_finding",
			Description: "Manually trigger validation for a finding. Runs secondary verification and PoC execution.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "string",
						"description": "ID of finding to validate",
					},
					"level": map[string]interface{}{
						"type":        "number",
						"description": "Validation level: 2 (verify only) or 3 (verify + PoC)",
					},
				},
				"required": []string{"finding_id"},
			},
		},

		// === EVIDENCE ===
		{
			Name:        "capture_evidence",
			Description: "Capture evidence for a finding: screenshots, HAR, video recording",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "string",
						"description": "Finding to capture evidence for",
					},
					"types": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Evidence types: screenshot, har, video, response",
					},
					"url": map[string]interface{}{
						"type":        "string",
						"description": "URL to capture (if not using finding's URL)",
					},
				},
				"required": []string{"types"},
			},
		},

		// === OPSEC ===
		{
			Name:        "opsec_setup",
			Description: "Setup OPSEC layer: proxy chains, MAC spoofing, VPN/Tor. Run before aggressive testing.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"proxy_chain": map[string]interface{}{
						"type":        "array",
						"description": "Proxy chain configuration",
					},
					"mac_spoof": map[string]interface{}{
						"type":        "boolean",
						"description": "Enable MAC address spoofing",
					},
					"tor": map[string]interface{}{
						"type":        "boolean",
						"description": "Route through Tor",
					},
					"vpn": map[string]interface{}{
						"type":        "string",
						"description": "VPN config file path",
					},
				},
			},
		},
		{
			Name:        "opsec_verify",
			Description: "Verify OPSEC setup is working. Checks IP, DNS leaks, proxy chain integrity.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"checks": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Checks to run: ip, dns, webrtc, mac",
					},
				},
			},
		},

		// === CONSULTATION ===
		{
			Name:        "consult_human",
			Description: "Ask the human operator for guidance when uncertain",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"question": map[string]interface{}{
						"type":        "string",
						"description": "Question for the human",
					},
					"context": map[string]interface{}{
						"type":        "string",
						"description": "Relevant context",
					},
					"options": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Options to choose from (if applicable)",
					},
					"category": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"logic", "scope", "technical", "priority", "opsec"},
						"description": "Question category",
					},
				},
				"required": []string{"question", "category"},
			},
		},

		// === DECISION LOGGING ===
		{
			Name:        "log_decision",
			Description: "Log a decision and reasoning to MongoDB for future learning",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"thinking": map[string]interface{}{
						"type":        "string",
						"description": "What you were thinking",
					},
					"decision": map[string]interface{}{
						"type":        "string",
						"description": "The decision made",
					},
					"reasoning": map[string]interface{}{
						"type":        "string",
						"description": "Why this decision",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Tags for categorization",
					},
				},
				"required": []string{"decision", "reasoning"},
			},
		},

		// === STATE & REPORTING ===
		{
			Name:        "get_findings",
			Description: "Get all findings, optionally filtered",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"state": map[string]interface{}{
						"type":        "string",
						"description": "Filter by state: DETECTED, VERIFIED, EXPLOITED, etc.",
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"description": "Filter by severity",
					},
				},
			},
		},
		{
			Name:        "generate_report",
			Description: "Generate professional vulnerability report",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"format": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"markdown", "html", "json"},
						"description": "Report format",
					},
					"platform": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"hackerone", "bugcrowd", "intigriti", "generic"},
						"description": "Platform-specific formatting",
					},
					"include_evidence": map[string]interface{}{
						"type":        "boolean",
						"description": "Include evidence files in report",
					},
				},
			},
		},

		// === WORKER MANAGEMENT ===
		{
			Name:        "list_workers",
			Description: "List running autonomous workers (fuzzers, crawlers)",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "stop_worker",
			Description: "Stop a running autonomous worker",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"worker_id": map[string]interface{}{
						"type":        "string",
						"description": "ID of worker to stop",
					},
				},
				"required": []string{"worker_id"},
			},
		},

		// === NEW: INGEST RESULT ===
		{
			Name:        "ingest_result",
			Description: "Push an ad-hoc finding into the system (MongoDB + memory). Use when you discover a vulnerability through manual testing, browser, or bash.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Finding title (e.g., 'IDOR on store-coupons API')",
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"critical", "high", "medium", "low", "info"},
						"description": "Severity level",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Detailed description of the finding",
					},
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Affected URL",
					},
					"vuln_type": map[string]interface{}{
						"type":        "string",
						"description": "Vulnerability type (e.g., idor, xss, sqli, auth-bypass)",
					},
					"endpoint": map[string]interface{}{
						"type":        "string",
						"description": "API endpoint path",
					},
					"method": map[string]interface{}{
						"type":        "string",
						"description": "HTTP method (GET, POST, etc.)",
					},
					"payload": map[string]interface{}{
						"type":        "string",
						"description": "Attack payload used",
					},
					"cwe": map[string]interface{}{
						"type":        "string",
						"description": "CWE identifier (e.g., CWE-639)",
					},
					"owasp": map[string]interface{}{
						"type":        "string",
						"description": "OWASP category (e.g., A01:2021)",
					},
					"raw_output": map[string]interface{}{
						"type":        "string",
						"description": "Raw output or evidence text",
					},
					"curl_command": map[string]interface{}{
						"type":        "string",
						"description": "Curl command for PoC reproduction",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Tags for categorization",
					},
				},
				"required": []string{"title"},
			},
		},

		// === NEW: RUN TOOL ===
		{
			Name:        "run_tool",
			Description: "Execute any registered plugin by name. Runs the actual binary, parses output, and saves findings to MongoDB.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Plugin name (e.g., subfinder, nuclei, httpx, ffuf, dalfox)",
					},
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Target domain",
					},
					"target": map[string]interface{}{
						"type":        "string",
						"description": "Target URL or host",
					},
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Target URL with parameters",
					},
					"extra_args": map[string]interface{}{
						"type":        "string",
						"description": "Additional command-line arguments",
					},
				},
				"required": []string{"name"},
			},
		},

		// === NEW: API TEST ===
		{
			Name:        "api_test",
			Description: "Authenticated API testing for IDOR detection and auth bypass. Supports differential comparison between two URLs and no-auth testing.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Primary URL to test",
					},
					"method": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
						"description": "HTTP method (default: GET)",
					},
					"authorization": map[string]interface{}{
						"type":        "string",
						"description": "Authorization header value (e.g., Bearer eyJ...)",
					},
					"headers": map[string]interface{}{
						"type":        "object",
						"description": "Additional headers as key-value pairs",
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Request body (for POST/PUT)",
					},
					"compare_url": map[string]interface{}{
						"type":        "string",
						"description": "Second URL to compare against (for IDOR differential proof)",
					},
					"test_no_auth": map[string]interface{}{
						"type":        "boolean",
						"description": "Also test without authorization header (auth bypass check)",
					},
				},
				"required": []string{"url"},
			},
		},

		// === NEW: HTTP REQUEST ===
		{
			Name:        "http_request",
			Description: "Simple HTTP request tool. Returns status, headers, and body. Use for quick endpoint probing.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "URL to request",
					},
					"method": map[string]interface{}{
						"type":        "string",
						"description": "HTTP method (default: GET)",
					},
					"headers": map[string]interface{}{
						"type":        "object",
						"description": "Request headers as key-value pairs",
					},
				},
				"required": []string{"url"},
			},
		},

		// === NEW: COMPARE RESPONSES (Phase 2 — Differential Analysis) ===
		{
			Name:        "compare_responses",
			Description: "Deep differential analysis between two API responses. Recursively compares JSON bodies, detects PII leaks, and auto-creates IDOR findings. Essential for proving IDOR vulnerabilities.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url1": map[string]interface{}{
						"type":        "string",
						"description": "First URL (e.g., user A's resource)",
					},
					"url2": map[string]interface{}{
						"type":        "string",
						"description": "Second URL (e.g., user B's resource)",
					},
					"method": map[string]interface{}{
						"type":        "string",
						"description": "HTTP method (default: GET)",
					},
					"headers": map[string]interface{}{
						"type":        "object",
						"description": "Common headers for both requests",
					},
					"auth1": map[string]interface{}{
						"type":        "string",
						"description": "Authorization header for request 1 (e.g., Bearer token_A)",
					},
					"auth2": map[string]interface{}{
						"type":        "string",
						"description": "Authorization header for request 2 (e.g., Bearer token_B)",
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Request body (for POST/PUT)",
					},
				},
				"required": []string{"url1", "url2"},
			},
		},

		// === NEW: DISCOVER CONFIG (Phase 3 — Intelligence Gathering) ===
		{
			Name:        "discover_config",
			Description: "Discover hidden config files, API endpoints from JS bundles, and hardcoded secrets. Probes 40+ known config paths and scans JS for API routes, tokens, and credentials.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Base URL of the application (e.g., https://example.com)",
					},
					"mode": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"full", "config", "js"},
						"description": "Discovery mode: 'full' (both), 'config' (paths only), 'js' (JavaScript only). Default: full",
					},
				},
				"required": []string{"url"},
			},
		},

		// === NEW: TEST WEBSOCKET (Phase 3 — WebSocket/STOMP Testing) ===
		{
			Name:        "test_websocket",
			Description: "Security testing for WebSocket and STOMP endpoints. Tests for CSWSH (Cross-Site WebSocket Hijacking), auth bypass, STOMP topic enumeration, and injection vulnerabilities.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "WebSocket URL (ws:// or wss://). HTTP URLs are auto-converted.",
					},
					"protocol": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"raw", "stomp"},
						"description": "Protocol type: 'raw' (plain WebSocket) or 'stomp' (STOMP over WS). Default: raw",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Auth token for testing auth bypass (tests with and without)",
					},
				},
				"required": []string{"url"},
			},
		},

		// === NEW: SET PROGRAM (Bounty Program Management) ===
		{
			Name:        "set_program",
			Description: "Register or switch to a bounty program. All subsequent findings, sessions, and tool runs will be tagged with this program slug. Creates the program in MongoDB if new, or reactivates if existing.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"slug": map[string]interface{}{
						"type":        "string",
						"description": "Unique slug for the program (e.g., 'playtika', 'hackerone-xyz')",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable program name",
					},
					"platform": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"hackerone", "bugcrowd", "intigriti", "synack", "independent"},
						"description": "Bug bounty platform (default: independent)",
					},
					"url": map[string]interface{}{
						"type":        "string",
						"description": "Program URL",
					},
					"in_scope": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "In-scope domains/assets",
					},
					"out_of_scope": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Out-of-scope domains/assets",
					},
					"payout_min": map[string]interface{}{
						"type":        "number",
						"description": "Minimum payout in USD",
					},
					"payout_max": map[string]interface{}{
						"type":        "number",
						"description": "Maximum payout in USD",
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "Any special notes about the program",
					},
				},
				"required": []string{"slug"},
			},
		},

		// === NEW: LIST PROGRAMS ===
		{
			Name:        "list_programs",
			Description: "List all registered bounty programs with their status, platform, and last activity. Shows which program is currently active.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},

		// === NEW: PROGRAM STATS ===
		{
			Name:        "program_stats",
			Description: "Get statistics for a bounty program: findings by severity, tool runs count, session count, and recent findings list.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{
						"type":        "string",
						"description": "Program slug (defaults to active program)",
					},
				},
			},
		},
	}
}

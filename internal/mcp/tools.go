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

		// === APP DOWNLOAD (APK/IPA Acquisition) ===
		{
			Name:        "download_app",
			Description: "Download mobile app binaries for analysis. Android: uses apkeep to download APKs from APKPure (NO AUTH needed), Google Play, or F-Droid. iOS: uses ipatool to download IPAs from App Store (needs Apple ID). Downloaded files can be passed to test_mobile for static analysis.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package_id": map[string]interface{}{
						"type":        "string",
						"description": "App package/bundle ID (e.g., com.instagram.android for Android, com.instagram.Instagram for iOS)",
					},
					"platform": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"android", "ios"},
						"description": "Target platform (default: android)",
					},
					"source": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"apkpure", "google-play", "f-droid", "appstore"},
						"description": "Download source. Android: apkpure (default, NO auth), google-play (needs email+token), f-droid. iOS: appstore (needs Apple ID).",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Output directory (default: /tmp/app_downloads)",
					},
					"email": map[string]interface{}{
						"type":        "string",
						"description": "Google account email (only for google-play source)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "AAS token for Google Play auth (only for google-play source)",
					},
				},
				"required": []string{"package_id"},
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
			Description: "Setup OPSEC layer. Set 'proxy' to route ALL request tools (http_request, api_test, compare_responses, discover_config) through an egress proxy — use this to unblock geo-restricted targets (e.g. a US proxy for US-only assets). Also supports MAC spoofing, VPN/Tor.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"proxy": map[string]interface{}{
						"type":        "string",
						"description": "Egress proxy URL applied to all request tools: http://host:port, https://host:port, or socks5://[user:pass@]host:port. This is the fix for geo-blocked targets.",
					},
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

		// === SANDBOX: EXECUTE HUNTING SCRIPT ===
		{
			Name: "execute_hunting_script",
			Description: "Execute a Python or Bash hunting script in a sandboxed environment. " +
				"All HTTP traffic is forced through mitmproxy (with scope enforcement). " +
				"Python scripts use an isolated venv (not host Python). " +
				"Secrets are injected via ephemeral env vars (never touch disk permanently). " +
				"Script code + stdout/stderr saved to named files in tests/ and artifacts/. " +
				"Returns last 2000 chars of output + path to full log file.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"code": map[string]interface{}{
						"type":        "string",
						"description": "The script source code to execute",
					},
					"runtime": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"python", "bash"},
						"description": "Script runtime: python (uses venv) or bash",
					},
					"script_name": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable name for the script (e.g., saml_replay_test, idor_user_enum). Used in filenames for evidence review.",
					},
					"secrets": map[string]interface{}{
						"type":        "object",
						"description": "Key-value secrets injected as env vars. Ephemeral — written to .env, loaded, then deleted. Never persists.",
					},
					"dependencies": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Extra pip packages to install in the venv before running (e.g., signxml, saml2). Only for Python runtime.",
					},
				},
				"required": []string{"code", "runtime"},
			},
		},

		// === EXHAUSTION LEDGER: LOG VECTOR STATUS ===
		{
			Name: "log_vector_status",
			Description: "Log the exhaustion status of an attack vector for deterministic termination. " +
				"Use this to track which vectors have been fully tested vs. which are still open. " +
				"EXHAUSTED = all test cases tried, no vuln found. " +
				"VULNERABLE = confirmed vulnerability on this vector. " +
				"BLOCKED_BY_DESIGN = cannot test (WAF, auth wall, scope restriction, etc).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"vector_id": map[string]interface{}{
						"type":        "string",
						"description": "Unique vector identifier (e.g., IDOR-/api/v1/users/{id}, XSS-search-param, SSRF-webhook-url)",
					},
					"state": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"EXHAUSTED", "VULNERABLE", "BLOCKED_BY_DESIGN"},
						"description": "Final state of this attack vector",
					},
					"rationale": map[string]interface{}{
						"type":        "string",
						"description": "Detailed rationale for this state (e.g., 'Tested 50 ID permutations across 3 endpoints, all returned 403 with consistent error body')",
					},
				},
				"required": []string{"vector_id", "state", "rationale"},
			},
		},

		// === V2 REVIEW PIPELINE ===
		{
			Name: "precheck_finding",
			Description: "Cheap deterministic pre-filter (NO LLM). Run BEFORE review_report to save tokens/time. " +
				"Hard-disqualifies out-of-scope and own-duplicate findings; warns on known false-positive classes " +
				"(public client keys, missing-header-only, self-XSS, spec-nitpicks); checks report completeness; " +
				"and scores value (payout × severity). review_report also runs this first and skips the panel if disqualified.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id":  map[string]interface{}{"type": "string", "description": "Stored finding to load, or use inline fields."},
					"title":       map[string]interface{}{"type": "string"},
					"description": map[string]interface{}{"type": "string"},
					"severity":    map[string]interface{}{"type": "string"},
					"vuln_type":   map[string]interface{}{"type": "string"},
					"target":      map[string]interface{}{"type": "string"},
					"url":         map[string]interface{}{"type": "string"},
					"poc":         map[string]interface{}{"type": "string"},
					"evidence":    map[string]interface{}{"type": "string"},
					"program":     map[string]interface{}{"type": "string", "description": "Defaults to active program."},
				},
			},
		},
		{
			Name: "review_report",
			Description: "Run the adversarial reviewer panel (OpenAI + NVIDIA models) over a candidate finding BEFORE submitting. " +
				"The panel are hostile triagers whose default is to REJECT — they raise the evidentiary bar with falsifiable evidence-demands. " +
				"Returns each model's verdict plus a conservative aggregate for YOU to arbitrate (you hold the most context). " +
				"Never auto-advances to submit-ready. Provide a finding_id (loaded from storage) OR inline finding fields.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id":    map[string]interface{}{"type": "string", "description": "ID of a stored finding to hydrate from MongoDB. Optional if inline fields are given."},
					"title":         map[string]interface{}{"type": "string", "description": "Finding title (if not using finding_id)."},
					"description":   map[string]interface{}{"type": "string", "description": "What the vulnerability is and why it matters."},
					"severity":      map[string]interface{}{"type": "string", "description": "Claimed severity (critical/high/medium/low/info)."},
					"vuln_type":     map[string]interface{}{"type": "string", "description": "Vulnerability class (idor, ssrf, cors, auth-bypass, ...). Used to pull matching lessons."},
					"target":        map[string]interface{}{"type": "string", "description": "Affected asset/host."},
					"url":           map[string]interface{}{"type": "string", "description": "Affected URL/endpoint."},
					"poc":           map[string]interface{}{"type": "string", "description": "Reproduction steps / request / curl demonstrating the issue."},
					"evidence":      map[string]interface{}{"type": "string", "description": "What was actually observed end-to-end (the proof of impact)."},
					"program":       map[string]interface{}{"type": "string", "description": "Program slug (defaults to active program)."},
					"program_scope": map[string]interface{}{"type": "string", "description": "Optional scope/rules override; otherwise loaded from the program record."},
				},
			},
		},
		{
			Name: "request_horizon",
			Description: "Ask the Director (a strong model) for NEW, untried attack hypotheses when you're stuck on the active program. " +
				"It is fed the exploration ledger (EXHAUSTED/BLOCKED/VULNERABLE vectors) and must not repeat them. " +
				"Output is hypotheses to TEST, not findings — each still has to pass the confirmation gate.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"notes": map[string]interface{}{"type": "string", "description": "What you've tried and why you're stuck — helps the director avoid dead ground."},
					"max":   map[string]interface{}{"type": "number", "description": "Max hypotheses to return (default 6)."},
				},
			},
		},
		{
			Name: "log_triage_outcome",
			Description: "Record the REAL verdict after a finding is submitted (the feedback loop that v1 lacked). " +
				"This is the single most valuable calibration signal — it powers review_stats and grounds future reviews. " +
				"A rejection with a reject_reason is auto-captured as a lesson.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id":    map[string]interface{}{"type": "string", "description": "The finding this outcome is for (optional but recommended)."},
					"program":       map[string]interface{}{"type": "string", "description": "Program slug (defaults to active program)."},
					"platform":      map[string]interface{}{"type": "string", "description": "hackerone / bugcrowd / intigriti / independent."},
					"platform_ref":  map[string]interface{}{"type": "string", "description": "Report id or URL on the platform."},
					"title":         map[string]interface{}{"type": "string", "description": "Finding title."},
					"vuln_type":     map[string]interface{}{"type": "string", "description": "Vulnerability class."},
					"severity":      map[string]interface{}{"type": "string", "description": "Severity."},
					"state":         map[string]interface{}{"type": "string", "enum": []string{"ACCEPTED", "DUPLICATE", "INFORMATIONAL", "NOT_APPLICABLE", "PENDING"}, "description": "The triager's verdict."},
					"reward_amount": map[string]interface{}{"type": "number", "description": "Bounty paid (0 if none)."},
					"currency":      map[string]interface{}{"type": "string", "description": "Currency (default USD when reward > 0)."},
					"reject_reason": map[string]interface{}{"type": "string", "description": "Why it was closed NA/dup/info — becomes a durable lesson."},
					"notes":         map[string]interface{}{"type": "string", "description": "Any extra context."},
				},
				"required": []string{"state"},
			},
		},
		{
			Name: "mark_submit_ready",
			Description: "Human-gated: advance a finding to SUBMIT_READY. Requires human_confirm=true. " +
				"Without confirmation it logs an approval request and refuses to advance — you cannot self-approve a submission.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id":    map[string]interface{}{"type": "string", "description": "The finding to mark ready."},
					"human_confirm": map[string]interface{}{"type": "boolean", "description": "Must be true, and only after a human has explicitly approved."},
					"note":          map[string]interface{}{"type": "string", "description": "Context for the approval record."},
				},
				"required": []string{"finding_id"},
			},
		},
		{
			Name:        "record_lesson",
			Description: "Manually capture a durable lesson / false-positive class for reviewer grounding (e.g. 'Braintree tokenization keys are public by design').",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"lesson":    map[string]interface{}{"type": "string", "description": "The guidance to remember."},
					"program":   map[string]interface{}{"type": "string", "description": "Scope to a program, or leave empty for a global lesson."},
					"vuln_type": map[string]interface{}{"type": "string", "description": "Scope to a vuln class."},
					"fp_class":  map[string]interface{}{"type": "string", "description": "Short slug, e.g. public-client-key, unexploited-cors, spec-nitpick."},
				},
				"required": []string{"lesson"},
			},
		},
		{
			Name:        "review_stats",
			Description: "Show the REAL scoreboard computed from triage outcomes (accept rate, total reward, breakdown by state/type) — not v1's self-labelled hit rate. Omit program for all-programs totals.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"program": map[string]interface{}{"type": "string", "description": "Program slug; omit for all programs."},
				},
			},
		},

		// === WIRELESS ATTACK CHAIN ===
		{
			Name: "wifi_attack",
			Description: "Orchestrated WPS/WPA2 attack chain against an AP you own. " +
				"Steps: enable monitor mode → wash WPS scan → reaver Pixie Dust → fallback brute-force (or handshake/PMKID path). " +
				"Requires a USB Wi-Fi adapter with monitor+injection support (e.g. Alfa AWUS036NHA) plugged into Kali Linux. " +
				"Does NOT work on macOS built-in Wi-Fi.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"interface": map[string]interface{}{
						"type":        "string",
						"description": "Wireless interface name before monitor mode (e.g. wlan0). Must be the USB adapter.",
					},
					"ssid": map[string]interface{}{
						"type":        "string",
						"description": "Target network name (SSID). Used to auto-detect BSSID from wash scan output.",
					},
					"bssid": map[string]interface{}{
						"type":        "string",
						"description": "Target AP MAC address (e.g. AA:BB:CC:DD:EE:FF). If omitted, auto-detected via wash scan.",
					},
					"channel": map[string]interface{}{
						"type":        "number",
						"description": "AP channel (1-13 for 2.4GHz, 36+ for 5GHz). Required when bssid is set manually.",
					},
					"attack": map[string]interface{}{
						"type": "string",
						"enum": []string{"wps_pixie", "wps_brute", "handshake", "pmkid"},
						"description": "Attack method: " +
							"wps_pixie=Pixie Dust then brute-force fallback (default, fastest); " +
							"wps_brute=bully WPS brute-force; " +
							"handshake=deauth+capture+aircrack-ng; " +
							"pmkid=passive PMKID capture+hashcat (no deauth needed).",
					},
					"wordlist": map[string]interface{}{
						"type":        "string",
						"description": "Path to wordlist for handshake/PMKID cracking (default: /usr/share/wordlists/rockyou.txt).",
					},
				},
				"required": []string{"interface"},
			},
		},
	}
}

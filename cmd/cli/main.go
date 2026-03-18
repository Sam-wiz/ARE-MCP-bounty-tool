// Package main provides the CLI wrapper for hack-ai-v2.
// This allows Copilot CLI, Gemini CLI, or any terminal AI to call tools directly.
//
// Usage:
//
//	hack-ai <command> [flags]
//	hack-ai program set --slug spotify --platform hackerone
//	hack-ai recon --domain spotify.com --mode deep
//	hack-ai scan --targets sub1.com,sub2.com --severity critical,high
//	hack-ai tool --name nmap --target 10.0.0.1
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/core"
	"github.com/samrudh/hack-ai-v2/internal/storage"
)

const version = "2.0.0"

// Global engine (initialized once)
var engine *core.Engine

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Handle help/version before engine init
	switch command {
	case "help", "--help", "-h":
		printUsage()
		return
	case "version", "--version", "-v":
		fmt.Printf("hack-ai v%s\n", version)
		return
	}

	// Initialize engine
	initEngine()

	// Route to command
	args := os.Args[2:]
	var exitCode int

	switch command {
	// === Program Management ===
	case "program":
		exitCode = cmdProgram(args)

	// === Target / Scope ===
	case "target":
		exitCode = cmdTarget(args)

	// === Reconnaissance ===
	case "recon":
		exitCode = cmdRecon(args)

	// === Scanning ===
	case "scan":
		exitCode = cmdScan(args)

	// === Injection Testing ===
	case "inject":
		exitCode = cmdInject(args)

	// === Cloud Testing ===
	case "cloud":
		exitCode = cmdCloud(args)

	// === Mobile Testing ===
	case "mobile":
		exitCode = cmdMobile(args)

	// === Fuzzing ===
	case "fuzz":
		exitCode = cmdFuzz(args)

	// === Run any plugin by name ===
	case "tool":
		exitCode = cmdTool(args)

	// === HTTP Request ===
	case "http":
		exitCode = cmdHTTP(args)

	// === API Testing ===
	case "api":
		exitCode = cmdAPI(args)

	// === Findings ===
	case "finding", "findings":
		exitCode = cmdFinding(args)

	// === Report ===
	case "report":
		exitCode = cmdReport(args)

	// === Evidence ===
	case "evidence":
		exitCode = cmdEvidence(args)

	// === OPSEC ===
	case "opsec":
		exitCode = cmdOpsec(args)

	// === Workers ===
	case "worker", "workers":
		exitCode = cmdWorker(args)

	// === Decision Logging ===
	case "decision":
		exitCode = cmdDecision(args)

	// === Advanced ===
	case "compare":
		exitCode = cmdCompare(args)
	case "config-discover":
		exitCode = cmdDiscoverConfig(args)
	case "websocket":
		exitCode = cmdWebSocket(args)

	default:
		// Try as a direct plugin name: hack-ai nmap --target ...
		exitCode = runDirectPlugin(command, args)
	}

	os.Exit(exitCode)
}

// ============================================================================
// ENGINE INIT
// ============================================================================

func initEngine() {
	cfgPath := "config/config.yaml"
	if p := os.Getenv("HACK_AI_CONFIG"); p != "" {
		cfgPath = p
	}
	cfg := config.LoadOrDefault(cfgPath)

	if envMongo := os.Getenv("MONGODB_URI"); envMongo != "" {
		cfg.MongoDB.URI = envMongo
	}
	if envRedis := os.Getenv("REDIS_ADDR"); envRedis != "" {
		cfg.Redis.Addr = envRedis
	}

	ctx := context.Background()

	mongoClient, err := storage.NewMongoClient(ctx, cfg.MongoDB.URI)
	if err != nil {
		log.Printf("MongoDB not available: %v (continuing without persistence)", err)
		mongoClient = nil
	}

	redisClient, _ := core.NewRedisClient(cfg.Redis.Addr)

	engine = core.NewEngine(core.EngineConfig{
		MongoDB: mongoClient,
		Redis:   redisClient,
		Config:  cfg,
	})
}

// ============================================================================
// COMMAND HANDLERS — each parses flags and calls engine.ExecuteTool
// ============================================================================

// --- Program ---
func cmdProgram(args []string) int {
	if len(args) == 0 {
		fmt.Println("Usage: hack-ai program <set|list|stats>")
		return 1
	}
	switch args[0] {
	case "set":
		p := parseFlags(args[1:])
		return call("set_program", map[string]interface{}{
			"slug":         p.get("slug", p.get("s", "")),
			"name":         p.get("name", p.get("n", "")),
			"platform":     p.get("platform", p.get("p", "independent")),
			"url":          p.get("url", ""),
			"in_scope":     splitCSV(p.get("scope", p.get("in-scope", ""))),
			"out_of_scope": splitCSV(p.get("out-of-scope", "")),
			"notes":        p.get("notes", ""),
		})
	case "list":
		return call("list_programs", map[string]interface{}{})
	case "stats":
		p := parseFlags(args[1:])
		return call("program_stats", map[string]interface{}{
			"program": p.get("program", p.get("p", "")),
		})
	default:
		fmt.Printf("Unknown program subcommand: %s\n", args[0])
		return 1
	}
}

// --- Target ---
func cmdTarget(args []string) int {
	if len(args) == 0 {
		fmt.Println("Usage: hack-ai target <set|validate>")
		return 1
	}
	switch args[0] {
	case "set":
		p := parseFlags(args[1:])
		return call("set_target", map[string]interface{}{
			"domain":       p.get("domain", p.get("d", "")),
			"in_scope":     splitCSV(p.get("scope", p.get("in-scope", ""))),
			"out_of_scope": splitCSV(p.get("out-of-scope", "")),
		})
	case "validate":
		p := parseFlags(args[1:])
		return call("validate_scope", map[string]interface{}{
			"target": p.get("target", p.get("t", firstPositional(args[1:]))),
		})
	default:
		fmt.Printf("Unknown target subcommand: %s\n", args[0])
		return 1
	}
}

// --- Recon ---
func cmdRecon(args []string) int {
	p := parseFlags(args)
	return call("recon_discover", map[string]interface{}{
		"domain": p.get("domain", p.get("d", firstPositional(args))),
		"mode":   p.get("mode", p.get("m", "deep")),
	})
}

// --- Scan ---
func cmdScan(args []string) int {
	p := parseFlags(args)
	return call("scan_vulnerabilities", map[string]interface{}{
		"targets":  splitCSV(p.get("targets", p.get("t", ""))),
		"severity": splitCSV(p.get("severity", p.get("s", "critical,high"))),
		"tags":     splitCSV(p.get("tags", "")),
	})
}

// --- Inject ---
func cmdInject(args []string) int {
	p := parseFlags(args)
	return call("test_injection", map[string]interface{}{
		"urls":  splitCSV(p.get("urls", p.get("u", ""))),
		"types": splitCSV(p.get("types", p.get("t", "xss,sqli"))),
	})
}

// --- Cloud ---
func cmdCloud(args []string) int {
	p := parseFlags(args)
	return call("test_cloud", map[string]interface{}{
		"target":   p.get("target", p.get("t", firstPositional(args))),
		"provider": p.get("provider", p.get("p", "aws")),
	})
}

// --- Mobile ---
func cmdMobile(args []string) int {
	p := parseFlags(args)
	return call("test_mobile", map[string]interface{}{
		"mode":     p.get("mode", p.get("m", "static")),
		"apk_path": p.get("apk", p.get("a", firstPositional(args))),
	})
}

// --- Fuzz ---
func cmdFuzz(args []string) int {
	p := parseFlags(args)
	return call("fuzz_target", map[string]interface{}{
		"target":   p.get("target", p.get("t", firstPositional(args))),
		"type":     p.get("type", "http"),
		"wordlist": p.get("wordlist", p.get("w", "")),
	})
}

// --- Tool (run any plugin) ---
func cmdTool(args []string) int {
	p := parseFlags(args)
	name := p.get("name", p.get("n", firstPositional(args)))
	if name == "" {
		fmt.Println("Usage: hack-ai tool --name <plugin_name> [--target <target>] [extra flags...]")
		return 1
	}

	toolArgs := map[string]interface{}{"name": name}
	// Pass through all other flags as plugin args
	for k, v := range p.flags {
		if k != "name" && k != "n" {
			toolArgs[k] = v
		}
	}
	return call("run_tool", toolArgs)
}

// --- HTTP ---
func cmdHTTP(args []string) int {
	p := parseFlags(args)
	return call("http_request", map[string]interface{}{
		"url":    p.get("url", p.get("u", firstPositional(args))),
		"method": p.get("method", p.get("m", "GET")),
	})
}

// --- API Test ---
func cmdAPI(args []string) int {
	p := parseFlags(args)
	m := map[string]interface{}{
		"url":    p.get("url", p.get("u", firstPositional(args))),
		"method": p.get("method", p.get("m", "GET")),
	}
	if auth := p.get("auth", p.get("authorization", "")); auth != "" {
		m["authorization"] = auth
	}
	if compare := p.get("compare", p.get("compare-url", "")); compare != "" {
		m["compare_url"] = compare
	}
	if p.get("no-auth", "") == "true" {
		m["test_no_auth"] = true
	}
	return call("api_test", m)
}

// --- Finding ---
func cmdFinding(args []string) int {
	if len(args) == 0 {
		fmt.Println("Usage: hack-ai finding <list|ingest|validate>")
		return 1
	}
	switch args[0] {
	case "list":
		p := parseFlags(args[1:])
		return call("get_findings", map[string]interface{}{
			"state":    p.get("state", ""),
			"severity": p.get("severity", ""),
		})
	case "ingest":
		p := parseFlags(args[1:])
		return call("ingest_result", map[string]interface{}{
			"title":       p.get("title", ""),
			"severity":    p.get("severity", p.get("s", "info")),
			"url":         p.get("url", ""),
			"vuln_type":   p.get("type", ""),
			"description": p.get("desc", p.get("description", "")),
			"endpoint":    p.get("endpoint", ""),
			"method":      p.get("method", ""),
			"payload":     p.get("payload", ""),
			"cwe":         p.get("cwe", ""),
			"owasp":       p.get("owasp", ""),
		})
	case "validate":
		p := parseFlags(args[1:])
		return call("validate_finding", map[string]interface{}{
			"finding_id": p.get("id", firstPositional(args[1:])),
		})
	default:
		fmt.Printf("Unknown finding subcommand: %s\n", args[0])
		return 1
	}
}

// --- Report ---
func cmdReport(args []string) int {
	p := parseFlags(args)
	return call("generate_report", map[string]interface{}{
		"format":   p.get("format", p.get("f", "markdown")),
		"platform": p.get("platform", p.get("p", "generic")),
	})
}

// --- Evidence ---
func cmdEvidence(args []string) int {
	p := parseFlags(args)
	return call("capture_evidence", map[string]interface{}{
		"types":      splitCSV(p.get("types", p.get("t", "screenshot,response"))),
		"url":        p.get("url", ""),
		"finding_id": p.get("finding-id", p.get("id", "")),
	})
}

// --- OPSEC ---
func cmdOpsec(args []string) int {
	if len(args) == 0 {
		fmt.Println("Usage: hack-ai opsec <setup|verify>")
		return 1
	}
	switch args[0] {
	case "setup":
		p := parseFlags(args[1:])
		m := map[string]interface{}{}
		if p.get("tor", "") == "true" {
			m["tor"] = true
		}
		if p.get("mac-spoof", "") == "true" {
			m["mac_spoof"] = true
		}
		if vpn := p.get("vpn", ""); vpn != "" {
			m["vpn"] = vpn
		}
		return call("opsec_setup", m)
	case "verify":
		return call("opsec_verify", map[string]interface{}{})
	default:
		fmt.Printf("Unknown opsec subcommand: %s\n", args[0])
		return 1
	}
}

// --- Worker ---
func cmdWorker(args []string) int {
	if len(args) == 0 || args[0] == "list" {
		return call("list_workers", map[string]interface{}{})
	}
	if args[0] == "stop" {
		p := parseFlags(args[1:])
		return call("stop_worker", map[string]interface{}{
			"worker_id": p.get("id", firstPositional(args[1:])),
		})
	}
	fmt.Printf("Unknown worker subcommand: %s\n", args[0])
	return 1
}

// --- Decision ---
func cmdDecision(args []string) int {
	p := parseFlags(args)
	return call("log_decision", map[string]interface{}{
		"decision":  p.get("decision", p.get("d", "")),
		"reasoning": p.get("reasoning", p.get("r", "")),
		"thinking":  p.get("thinking", ""),
		"tags":      splitCSV(p.get("tags", "")),
	})
}

// --- Advanced ---
func cmdCompare(args []string) int {
	p := parseFlags(args)
	return call("compare_responses", map[string]interface{}{
		"url1": p.get("url1", ""),
		"url2": p.get("url2", ""),
	})
}

func cmdDiscoverConfig(args []string) int {
	p := parseFlags(args)
	return call("discover_config", map[string]interface{}{
		"url": p.get("target", p.get("t", firstPositional(args))),
	})
}

func cmdWebSocket(args []string) int {
	p := parseFlags(args)
	return call("test_websocket", map[string]interface{}{
		"url":      p.get("url", p.get("u", firstPositional(args))),
		"messages": splitCSV(p.get("messages", p.get("m", ""))),
	})
}

// --- Direct plugin: hack-ai nmap --target 10.0.0.1 ---
func runDirectPlugin(name string, args []string) int {
	p := parseFlags(args)
	toolArgs := map[string]interface{}{"name": name}
	for k, v := range p.flags {
		toolArgs[k] = v
	}
	return call("run_tool", toolArgs)
}

// ============================================================================
// CORE: call engine and print result
// ============================================================================

func call(toolName string, args map[string]interface{}) int {
	// Remove empty args
	clean := make(map[string]interface{})
	for k, v := range args {
		switch val := v.(type) {
		case string:
			if val != "" {
				clean[k] = val
			}
		case []interface{}:
			if len(val) > 0 {
				clean[k] = val
			}
		default:
			if v != nil {
				clean[k] = v
			}
		}
	}

	ctx := context.Background()
	result, err := engine.ExecuteTool(ctx, toolName, clean)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	for _, block := range result.Content {
		fmt.Print(block.Text)
	}
	fmt.Println()

	if result.IsError {
		return 1
	}
	return 0
}

// ============================================================================
// FLAG PARSING — lightweight, no external deps
// ============================================================================

type flagSet struct {
	flags       map[string]string
	positionals []string
}

func parseFlags(args []string) *flagSet {
	fs := &flagSet{
		flags:       make(map[string]string),
		positionals: []string{},
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			if strings.Contains(key, "=") {
				parts := strings.SplitN(key, "=", 2)
				fs.flags[parts[0]] = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				fs.flags[key] = args[i+1]
				i++
			} else {
				fs.flags[key] = "true"
			}
		} else if strings.HasPrefix(arg, "-") && len(arg) == 2 {
			key := strings.TrimPrefix(arg, "-")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fs.flags[key] = args[i+1]
				i++
			} else {
				fs.flags[key] = "true"
			}
		} else {
			fs.positionals = append(fs.positionals, arg)
		}
	}
	return fs
}

func (fs *flagSet) get(key, fallback string) string {
	if v, ok := fs.flags[key]; ok {
		return v
	}
	return fallback
}

func firstPositional(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func splitCSV(s string) []interface{} {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]interface{}, len(parts))
	for i, p := range parts {
		result[i] = strings.TrimSpace(p)
	}
	return result
}

// ============================================================================
// HELP
// ============================================================================

func printUsage() {
	help := `
╔══════════════════════════════════════════════════════════════╗
║   hack-ai v` + version + ` — Bug Bounty CLI                          ║
║   154 Tools | MongoDB Logging | Scope Enforcement            ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    hack-ai <command> [flags]

PROGRAM & SCOPE:
    hack-ai program set --slug <slug> --platform <platform> [--scope "*.example.com"]
    hack-ai program list
    hack-ai program stats [--program <slug>]
    hack-ai target set --domain <domain> --scope "*.domain.com" [--out-of-scope "admin.domain.com"]
    hack-ai target validate <target>

RECONNAISSANCE:
    hack-ai recon --domain <domain> [--mode passive|active|deep]
    hack-ai recon <domain>

SCANNING:
    hack-ai scan --targets sub1.com,sub2.com [--severity critical,high]
    hack-ai inject --urls <url1,url2> [--types xss,sqli]
    hack-ai fuzz --target <url> [--type http|api] [--wordlist <path>]
    hack-ai cloud --target <target> [--provider aws|gcp|azure]
    hack-ai mobile --apk <path.apk> [--mode static|dynamic|full]

DIRECT TOOL EXECUTION:
    hack-ai tool --name <plugin_name> [--target <target>] [extra flags...]
    hack-ai <plugin_name> [--target <target>]    ← shorthand (e.g., hack-ai nmap --target 10.0.0.1)

HTTP & API TESTING:
    hack-ai http --url <url> [--method GET|POST]
    hack-ai api --url <url> [--auth "Bearer xxx"] [--compare <url2>] [--no-auth]

FINDINGS:
    hack-ai finding list [--state detected|verified] [--severity critical|high]
    hack-ai finding ingest --title "XSS in Search" --severity high --url <url> --type xss
    hack-ai finding validate <finding_id>

REPORTING:
    hack-ai report [--format markdown|json] [--platform hackerone|bugcrowd|generic]
    hack-ai evidence [--types screenshot,response] [--url <url>] [--id <finding_id>]

OPSEC:
    hack-ai opsec setup [--tor] [--mac-spoof] [--vpn <config>]
    hack-ai opsec verify

WORKERS:
    hack-ai worker list
    hack-ai worker stop <worker_id>

ADVANCED:
    hack-ai compare --url1 <url> --url2 <url>
    hack-ai config-discover --target <target>
    hack-ai websocket --url <ws://url> --messages "msg1,msg2"
    hack-ai decision --decision "text" --reasoning "text" [--tags "tag1,tag2"]

ENVIRONMENT VARIABLES:
    MONGODB_URI      MongoDB connection string (default: mongodb://localhost:27017)
    REDIS_ADDR       Redis address (default: localhost:6379)
    HACK_AI_CONFIG   Config file path (default: config/config.yaml)

EXAMPLES:
    hack-ai program set --slug spotify --platform hackerone --scope "*.spotify.com"
    hack-ai target set --domain spotify.com --scope "*.spotify.com"
    hack-ai recon spotify.com
    hack-ai scan --targets sub1.spotify.com,sub2.spotify.com --severity critical,high
    hack-ai nmap --target 10.0.0.1 --flags "-sV -sC"
    hack-ai finding list --severity critical
    hack-ai report --platform hackerone
`
	fmt.Print(help)
	fmt.Fprintf(os.Stderr, "\n")

	// Also try to print a JSON dump of available tools for AI consumption
	if os.Getenv("HACK_AI_JSON_HELP") == "1" {
		tools := map[string]interface{}{
			"version":  version,
			"commands": []string{"program", "target", "recon", "scan", "inject", "cloud", "mobile", "fuzz", "tool", "http", "api", "finding", "report", "evidence", "opsec", "worker", "decision", "compare", "config-discover", "websocket"},
		}
		data, _ := json.MarshalIndent(tools, "", "  ")
		fmt.Fprintln(os.Stderr, string(data))
	}
}

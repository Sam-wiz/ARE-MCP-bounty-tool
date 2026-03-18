# hack-ai-v2 — AI-Powered Bug Bounty Automation

> An MCP server + CLI tool that connects any AI model to **158 security tools**, automating the full bug bounty workflow: recon → scan → finding tracking → report generation.

---

## What Is This?

hack-ai-v2 exposes **28 MCP tools** that any AI assistant (Claude, Copilot, Gemini, Cursor, Cline) can use to run real security tools on your machine. You describe what you want in natural language. The AI calls the right tools in sequence. Everything gets logged to MongoDB.

**Two binaries:**
- `bin/hack-ai-v2` — MCP server (stdio JSON-RPC, for Claude Code / Cursor / Cline / Copilot)
- `bin/hack-ai` — CLI wrapper (for terminal AIs or direct use)

---

## Architecture

```
AI Model (Claude / Copilot / Gemini)
    │
    │  stdio JSON-RPC (MCP protocol)
    ▼
hack-ai-v2 binary  ─────── MongoDB (audit log + findings)
    │                       Redis  (async workers)
    ▼
Plugin Engine (154 YAML-defined tools)
    │
    ▼
Real CLI tools: subfinder, nuclei, sqlmap, nmap, frida, ffuf...
```

Every tool call is scope-validated, logged, and tracked as part of a bounty program.

---

## Prerequisites

| Dependency | Purpose | Install |
|---|---|---|
| Go 1.21+ | Build the binaries | `brew install go` |
| MongoDB Atlas or local | Findings + audit log | [atlas.mongodb.com](https://www.mongodb.com/atlas) or `brew install mongodb-community` |
| Redis | Async workers | `brew install redis` |
| Security tools | Actual scanning | `./scripts/install_tools.sh --all` |

---

## Installation

### 1. Clone and configure

```bash
git clone <repo-url> hack-ai-v2
cd hack-ai-v2

# Copy example config and fill in your MongoDB URI
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml — set mongodb_uri
```

### 2. Install security tools

```bash
# Install all 158 tools (takes 10-20 min, requires brew + pip + go)
./scripts/install_tools.sh --all

# Or install by category
./scripts/install_tools.sh --essentials   # Top 10 core tools
./scripts/install_tools.sh --go           # 52 Go-based tools
./scripts/install_tools.sh --python       # 32 Python tools
./scripts/install_tools.sh --system       # 24 brew/apt tools
./scripts/install_tools.sh --opsec        # VPN + MAC spoof tools

# Verify what is installed
./scripts/check_tools.sh
```

### 3. Build

```bash
# Build both binaries
make build

# Output:
#   bin/hack-ai-v2   (MCP server)
#   bin/hack-ai      (CLI wrapper)
```

### 4. Start dependencies

```bash
brew services start redis
# MongoDB: ensure your URI in config/config.yaml is reachable
```

---

## Usage: MCP Server (Recommended)

Connect `bin/hack-ai-v2` to your AI assistant. The AI will have access to all 28 tools automatically.

### Claude Code

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hack-ai-v2": {
      "command": "/absolute/path/to/hack-ai-v2/bin/hack-ai-v2",
      "args": [],
      "env": {
        "MONGODB_URI": "mongodb+srv://user:pass@cluster.mongodb.net/?appName=hack-ai-v2"
      }
    }
  }
}
```

Or project-level — create `.mcp.json` in any project root:

```json
{
  "mcpServers": {
    "hack-ai-v2": {
      "command": "/absolute/path/to/hack-ai-v2/bin/hack-ai-v2"
    }
  }
}
```

### Cursor

Settings -> MCP Servers -> Add, or create `.cursor/mcp.json`:

```json
{
  "hack-ai-v2": {
    "command": "/absolute/path/to/hack-ai-v2/bin/hack-ai-v2",
    "env": { "MONGODB_URI": "your-uri" }
  }
}
```

### GitHub Copilot CLI

```bash
# Flag
copilot --mcp-server hack-ai-v2=/absolute/path/to/bin/hack-ai-v2

# Or config: ~/.config/github-copilot/mcp.json
{
  "servers": {
    "hack-ai-v2": { "command": "/absolute/path/to/bin/hack-ai-v2" }
  }
}
```

### Gemini CLI

Config at `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "hack-ai-v2": { "command": "/absolute/path/to/bin/hack-ai-v2" }
  }
}
```

### Cline (VS Code)

Cline sidebar -> MCP Servers -> Configure -> add the server JSON block.

### HTTP bridge (any LLM)

```bash
npx -y supergateway --port 3000 /absolute/path/to/bin/hack-ai-v2
```

---

## Usage: CLI Wrapper (`hack-ai`)

The `hack-ai` binary wraps all 28 engine tools into shell commands — useful for terminal AIs or direct scripting.

```bash
# Optional: install globally
sudo make install   # symlinks bin/hack-ai to /usr/local/bin/hack-ai
```

### Full hunting session example

```bash
# 1. Set the bounty program (ALWAYS do this first)
hack-ai program set --slug shopify --platform hackerone --scope "*.shopify.com"

# 2. Set and validate the target
hack-ai target set --domain shopify.com --scope "*.shopify.com" --out-of-scope "community.shopify.com"

# 3. Deep recon (runs subfinder + amass + httpx + gau + katana + nuclei)
hack-ai recon shopify.com --mode deep

# 4. Scan discovered subdomains for vulnerabilities
hack-ai scan --targets sub1.shopify.com,sub2.shopify.com --severity critical,high

# 5. Run a specific tool directly (any of 154 plugins)
hack-ai nuclei --target https://api.shopify.com
hack-ai sqlmap --url "https://api.shopify.com/search?q=test"
hack-ai nmap --target 23.227.38.0 --flags "-sV -sC"

# 6. Review findings
hack-ai finding list --severity critical

# 7. Generate report
hack-ai report --format markdown --platform hackerone
```

### Full command reference

```bash
# Program & scope
hack-ai program set --slug <slug> --platform <platform> [--scope "*.example.com"]
hack-ai program list
hack-ai program stats
hack-ai target set --domain <domain> --scope "glob" [--out-of-scope "glob"]
hack-ai target validate <url>

# Recon & scanning
hack-ai recon <domain> [--mode passive|active|deep]
hack-ai scan --targets <t1,t2> [--severity critical,high]
hack-ai inject --urls <u1,u2> [--types xss,sqli]
hack-ai fuzz --target <url> [--type http|api]
hack-ai cloud --target <t> [--provider aws|gcp|azure]
hack-ai mobile --apk <path> [--mode static|dynamic|full]

# Direct plugin execution (any of 154 plugins)
hack-ai tool --name <plugin>
hack-ai <plugin_name> --target <t>   # shorthand

# HTTP & API testing
hack-ai http --url <url> [--method GET|POST]
hack-ai api --url <url> [--auth "Bearer xxx"] [--compare <url2>] [--no-auth]

# Findings
hack-ai finding list [--state detected|verified] [--severity critical|high]
hack-ai finding ingest --title "XSS in search" --severity high --url <url> --type xss
hack-ai finding validate <id>

# Reporting & evidence
hack-ai report [--format markdown|json] [--platform hackerone|bugcrowd|yeswehack]
hack-ai evidence [--types screenshot,response] [--url <url>]

# OPSEC
hack-ai opsec setup [--tor] [--mac-spoof] [--vpn <config>]
hack-ai opsec verify

# Workers & advanced
hack-ai worker list
hack-ai worker stop <id>
hack-ai compare --url1 <url> --url2 <url>
hack-ai config-discover --target <target>
hack-ai websocket --url <ws://url> --messages "msg1,msg2"
```

---

## Critical Rule: Always Set Program First

> **Call `set_program` / `hack-ai program set` BEFORE doing anything else in every session.**

Every scan, finding, and log entry is tagged with the active program slug. Without it, data goes nowhere — and mixing programs risks accidental out-of-scope testing, which can get you banned from platforms.

Each program gets an isolated workspace:

```
~/bounty-programs/bounty-<slug>/
├── recon/          subdomains, urls, ports, technologies
├── findings/       raw/ and verified/
├── evidence/       screenshots/, har/, videos/
├── reports/        draft/ and final/
├── notes/
├── poc/
├── logs/
└── .workspace.json
```

---

## 28 MCP Tools Reference

| Category | Tools |
|---|---|
| Program/scope | `set_program`, `list_programs`, `program_stats`, `set_target`, `validate_scope` |
| Recon | `recon_discover` |
| Scanning | `scan_vulnerabilities`, `test_injection`, `test_cloud`, `test_mobile`, `fuzz_target` |
| Direct execution | `run_tool`, `http_request`, `api_test` |
| Findings | `ingest_result`, `validate_finding`, `get_findings`, `generate_report`, `capture_evidence` |
| OPSEC | `opsec_setup`, `opsec_verify` |
| Decision | `consult_human`, `log_decision`, `list_workers`, `stop_worker` |
| Advanced | `compare_responses`, `discover_config`, `test_websocket` |

---

## Tool Arsenal (158 Tools)

### Recon (58)
subfinder, amass, findomain, chaos, httpx, httprobe, katana, gospider, hakrawler, meg, gau, waybackurls, dnsx, shuffledns, puredns, massdns, naabu, masscan, nmap, rustscan, arjun, paramspider, kiterunner, linkfinder, getjs, gowitness, eyewitness, shodan, censys, uncover, alterx, dnsgen, gotator, dnstwist, assetfinder, asnmap, tlsx, wafw00f, whatweb, theharvester, reconftw, fierce, dnsrecon, knockpy, unfurl, gf, anew, gron, qsreplace

### Web Vulnerability Scanning (36)
nuclei, dalfox, xsstrike, sqlmap, ghauri, tplmap, commix, ssrfmap, xxeinjector, nikto, ffuf, feroxbuster, gobuster, dirsearch, wfuzz, crlfuzz, jaeles, subjack, subover, subzy, subdominator, bypass403, corsy, smuggler, nosqlmap, graphqlmap, cmsmap, joomscan, wpscan, droopescan, openredirex, shcheck, lfisuite, interactsh

### Network & Infrastructure (17)
nmap, masscan, rustscan, sslscan, sslyze, testssl, smbclient, smbmap, enum4linux, ldapsearch, crackmapexec, impacket, bloodhound, responder, tcpdump, tshark

### Auth & Exploitation (7)
hydra, hashcat, john, jwt_tool, kerbrute, metasploit, searchsploit

### Secrets & Source Code (6)
trufflehog, gitleaks, secretfinder, gitdorker, githound, gittools

### Cloud Security (4)
prowler, scoutsuite, s3scanner, cloudenum

### Mobile Security (10)
adb, android_emulator, frida, objection, apktool, jadx, drozer, mobsf, sdkmanager, avdmanager

### OPSEC (4)
protonvpn-cli, proxychains-ng, spoofmac, macchanger

### Utility (11)
anew, gf, gron, qsreplace, unfurl, uro, cewl, crunch, cupp, notify, jq

### Wordlists (3)
SecLists, PayloadsAllTheThings, OneListForAll

---

## OPSEC

```bash
./scripts/setup_opsec.sh --connect US      # ProtonVPN to US exit node
./scripts/setup_opsec.sh --connect JP      # Switch to Japan
./scripts/setup_opsec.sh --spoof-mac       # Randomize MAC address
./scripts/setup_opsec.sh --full DE         # Full: MAC + Tor + VPN (Germany)
./scripts/setup_opsec.sh --status          # Check current state
./scripts/setup_opsec.sh --teardown        # Restore everything
```

Always run `hack-ai opsec verify` before starting a live hunt to confirm your real IP is not exposed.

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017` |
| `REDIS_ADDR` | Redis address | `localhost:6379` |
| `HACK_AI_CONFIG` | Config file path | `config/config.yaml` |

---

## Adding a Plugin

Tools are defined as YAML in `plugins/core/<category>/`. To add a new tool:

```yaml
name: mytool
category: recon
description: "Does something useful"
install:
  method: go
  command: go install github.com/user/mytool@latest
  verify: mytool --version
execute:
  command: "mytool {flags} {target}"
  input:
    target: { type: string, required: true }
    flags:  { type: string, default: "-silent" }
  timeout: 120
```

That's it — the tool is immediately available via `run_tool(name="mytool")` or `hack-ai mytool --target <t>`.

---

## Makefile Targets

```bash
make build          # Build both binaries
make build-cli      # Build only hack-ai CLI
make test           # Run all tests
make vet            # Run go vet
make cover          # Tests with coverage report
make install-tools  # Install all 158 security tools
make check-tools    # Health check all tools
make check-recon    # Health check recon tools only
make check-web      # Health check web scanning tools
make clean          # Remove build artifacts
make ci             # vet + test + build (full pipeline)
make install        # Install hack-ai to /usr/local/bin
```

---

## Project Structure

```
hack-ai-v2/
├── cmd/
│   ├── server/         MCP server entrypoint
│   └── cli/            CLI wrapper entrypoint
├── internal/
│   ├── core/           Engine, handlers (recon/scan/api/mobile), executor
│   ├── mcp/            MCP protocol server + tool registration
│   ├── storage/        MongoDB + Redis clients
│   ├── types/          Shared types
│   └── workers/        Async background workers
├── plugins/
│   └── core/           YAML plugin definitions (158 tools)
│       ├── recon/
│       ├── scanner/
│       ├── fuzzer/
│       ├── exploit/
│       ├── mobile/
│       ├── cloud/
│       ├── network/
│       ├── osint/
│       └── util/
├── config/
│   ├── config.example.yaml
│   ├── opsec.yaml
│   └── checklists/
├── scripts/
│   ├── install_tools.sh
│   ├── check_tools.sh
│   └── setup_opsec.sh
├── bin/                (generated by make build — gitignored)
├── Makefile
└── go.mod
```

---

## Roadmap

### Near Term
- [ ] **Docker stack** — `docker compose up` brings the full stack (hack-ai-v2 + MongoDB + Redis + tools) with zero host installs
- [ ] **Scope-specific images** — Lean containers per attack surface: `hack-ai-web`, `hack-ai-mobile`, `hack-ai-network`, `hack-ai-cloud`
- [ ] **Tool execution optimization** — Parallel recon phases, streaming output for long-running scans, subprocess pooling

### Medium Term
- [ ] **Expanded CLI** — Interactive TUI mode, shell completions (bash/zsh/fish), real-time progress bars
- [ ] **Plugin marketplace** — Community YAML plugins with signature verification and `hack-ai plugin install <name>`
- [ ] **Diff-based scanning** — Track asset changes across sessions; only re-scan new/changed targets
- [ ] **Rate limiting layer** — Per-domain request throttling and politeness controls

### Longer Term
- [ ] **Web dashboard** — React UI for findings, programs, evidence, and report generation
- [ ] **Platform API integration** — Auto-submit verified findings to HackerOne / Bugcrowd / YesWeHack APIs
- [ ] **Collaborative mode** — Multi-user workspaces with shared findings and RBAC
- [ ] **Workflow templates** — Pre-built hunting flows per program type (web, API, mobile, cloud) that chain tools optimally

---

## Legal

For authorized security testing only. Always obtain written permission before testing any target. Scope validation is enforced by the tool, but legal responsibility for authorized use remains with the operator.

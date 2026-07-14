# hack-ai-v2 (ARE-MCP-bounty tool)

An automated bug-bounty engine. It exposes a large set of security tools over the
Model Context Protocol (MCP), and an LLM agent (Claude Code) drives them to do
recon, probe for vulnerabilities, and write up findings. All state lives in MongoDB.

The interesting part isn't the tool wrapping — it's the layer that sits *between*
"the model thinks it found a bug" and "you submit it," because that's where an
autonomous hunter usually goes wrong.

---

## TL;DR

- **What:** a Go MCP server that turns any MCP-capable LLM into an autonomous bug-bounty hunter, backed by ~150 offensive security tools and MongoDB state.
- **The twist:** every finding passes through a **deterministic pre-filter + an adversarial multi-LLM review panel + a human gate** before it can be submitted — so the engine can't spam a program with theoretical junk (which is exactly what its first version did).
- **The honest bit:** I tried to train the reviewer to *predict* accept/reject from a report's text, measured that it caps at ~48% six different ways, and redesigned around that result instead of hiding it.

---

## Why it exists

The first version of this engine had a problem I could measure: over four months
it flagged **105 attack vectors as "VULNERABLE" and earned about $0**. 

It overclaimed constantly — "CONFIRMED!" for things that were theoretical — stopped
at indicators instead of proving impact, and had no memory of what actually
worked. The one finding that ever paid (~$1,100) wasn't even in the database.

So v2 is built around a single idea: **an LLM that hunts will produce far more
"findings" than are real, so the engine needs a gate that's skeptical by default
and grounded in real outcomes** — not another model that's eager to agree with
itself.

---

## Engineering highlights

- Custom **MCP server in Go** exposing ~40 first-class tools + a plugin bridge to ~150 CLI security tools
- **Adversarial multi-LLM review pipeline** — different models cross-check each finding as hostile triagers, aggregated by a majority-block rule
- **Deterministic finding lifecycle** — a 12-state machine, not an ad-hoc "is it a bug?" flag
- **Mongo-backed memory + RAG** over real historical submissions, so the reviewer learns from your actual triage outcomes
- **Scope enforcement** at two layers — in the Go request tools *and* in a mitmproxy interceptor for sandboxed scripts, so a redirect can't wander out of scope
- **Sandboxed Bash/Python execution** with per-program workspaces, venvs, timeouts, and proxied traffic
- **Egress proxy layer** so all outbound testing can route through a chosen exit (geo-restricted targets)
- **Transcript archival** of every agent session into Mongo (a growing RLHF corpus), via a Claude Code Stop hook
- **Offline backtesting harness** that scores the reviewer against real historical verdicts

---

## Architecture

```
        ┌──────────────────────┐
        │   LLM agent (Claude) │   drives the hunt, decides what to test
        └──────────┬───────────┘
                   │  MCP (JSON-RPC over stdio)
        ┌──────────▼───────────────────────────────────────────┐
        │            Go engine  (cmd/server)                    │
        │                                                       │
        │  scope/recon/http tools ── egress proxy ──► targets   │
        │  execute_hunting_script ─ mitmproxy (scope) ─► targets │
        │                                                       │
        │  ┌─────────────── review pipeline ────────────────┐   │
        │  │ precheck ─► reviewer panel ─► human gate        │   │
        │  │ (rules)     (multi-model)     (you approve)      │   │
        │  └──────────────────┬──────────────────────────────┘   │
        └─────────────────────┼─────────────────────────────────┘
                              │
                ┌─────────────▼──────────────┐        ┌───────────────────┐
                │   MongoDB (Atlas)          │        │  OpenAI / NVIDIA  │
                │  findings, decisions,      │        │  reviewer panel + │
                │  triage_outcomes, lessons, │◄──────►│  embeddings (RAG) │
                │  reviews, transcripts      │        └───────────────────┘
                └────────────────────────────┘
```

Two binaries: `cmd/server` (the MCP server the agent talks to) and `cmd/cli`
(local queries). Config comes from a gitignored `.env` (Mongo URI, LLM keys)
plus `config/config.yaml`.

### A finding, end to end

```
Claude picks a vector
      ↓
recon / http_request / execute_hunting_script  (scope-enforced, proxied)
      ↓
candidate finding
      ↓
precheck        → out-of-scope? own-dup? known FP-class? value score   (free, no LLM)
      ↓
review_report   → adversarial panel demands a real PoC; emits evidence-demands
      ↓            (loop: go prove impact, re-review, until it clears)
mark_submit_ready → HUMAN approves
      ↓
you submit → log_triage_outcome → scoreboard + auto-generated lessons
      ↓
future reviews retrieve this outcome (RAG) and don't repeat the mistake
```

---

## The review pipeline

A candidate finding moves through a gated lifecycle instead of being declared
"VULNERABLE" on the spot:

```
CANDIDATE → REPRODUCED → IMPACT_PROVEN → SURVIVED_SKEPTIC
          → REPORT_DRAFTED → SUBMIT_READY → SUBMITTED
          → {ACCEPTED | DUPLICATE | INFORMATIONAL | NOT_APPLICABLE}
```

---

## How the pieces actually work

### Sandboxed execution
`execute_hunting_script` runs agent-written Python/Bash. It is **process-level
isolation, not a kernel sandbox** (no seccomp/namespaces — worth being honest
about): each program gets its own filesystem **workspace** (`cmd.Dir`), its own
**Python venv**, a controlled **environment**, and a hard **timeout** (default
10 min, configurable). Outbound traffic is pushed through **mitmproxy** running
`scripts/scope_enforcer.py`, which is what actually keeps a script from talking to
out-of-scope hosts and simultaneously captures the traffic for evidence.

### Scope enforcement (two layers)
- **In the Go tools:** every request tool (`http_request`, `api_test`,
  `compare_responses`, discovery) validates the target host against the active
  program scope before firing. Matching is case-insensitive and understands
  **path-scoped entries** (`host/testing-path/`) and **apex wildcards**
  (`*.example.com` matches subdomains *and* the apex).
- **In the sandbox:** the mitmproxy `scope_enforcer` blocks out-of-scope requests
  a script might make via a redirect — so `in-scope.com → 302 → evil.com` doesn't
  quietly leave scope.

### Memory / RAG
Past triage threads are embedded with `text-embedding-3-small` and stored inline
on the document. At review time the engine embeds the current finding and does a
**brute-force cosine** search — **top-3** neighbors above a **0.30** similarity
threshold — and injects those real prior verdicts into the panel prompt. No vector
DB (see decisions below).

### Data model (Mongo, ~14 collections)
```
findings        lifecycle state, severity, PoC, evidence, CWE/OWASP, tags
decisions       every tool call + captured model reasoning
reviews         each panel round: per-model verdicts + aggregate + demands
triage_outcomes real program verdicts + reward   → the scoreboard
lessons         auto-generated from rejections   → reviewer grounding
triage_threads  full researcher↔triager threads + embeddings (RAG)
transcripts     archived agent sessions (RLHF corpus)
programs · sessions · tool_runs · vector_statuses · script_executions · hypotheses
```

---


## A note on calibration (Jul 2026)

I tried to make the reviewer *predict* whether a triager would accept or reject a
finding, using 26 of my real Bugcrowd submissions as ground truth. It doesn't
work, and I proved it six ways — panel aggregation, embedding similarity, a
targeted "is the exploit demonstrated" feature, and retrieval-augmented few-shot
all land at ~48% accuracy, and any config aggressive enough to catch the rejects
also kills the findings that actually paid.

The reason is structural: the signal separating accepted from rejected **isn't in
the report text**. A triager decides on reproduction, program policy, and
duplicate timing — information the classifier never sees. The result shaped the design:
the reviewer stays a *skeptical gate* (bias toward "prove it"), and the real
accept/reject signal comes from actually attempting the exploit, not a smarter
classifier.

---

## Quick start

```bash
make build                  # → bin/hack-ai-v2 (server) + bin/hack-ai (cli)
cp .env.example .env         # fill MONGODB_URI + OPENAI_API_KEY / NVIDIA_API_KEY
./scripts/install_tools.sh --all      # (optional) the CLI security tools
```

Point your MCP client at `bin/hack-ai-v2`:

```json
{
  "mcpServers": {
    "hack-ai-v2": {
      "command": "/abs/path/to/hack-ai-v2/bin/hack-ai-v2",
      "env": { "HACK_AI_CONFIG": "/abs/path/to/hack-ai-v2/config/config.yaml" }
    }
  }
}
```

Typical session flow:

```
set_program → set_target → recon_discover / http_request / api_test / execute_hunting_script
log_vector_status → precheck_finding → review_report → mark_submit_ready → log_triage_outcome
```

---

## Project layout

```
cmd/
  server/        MCP server (the thing the agent talks to)
  cli/           local queries / stats
  migrate/       import the v1 snapshot into the v2 cluster
  importsubs/    load Bugcrowd exports → outcomes + lessons + RAG threads
  embedthreads/  embed triage threads for retrieval
  backtest/      score the reviewer against real historical verdicts
  synclog/       Stop-hook binary that archives session transcripts to Mongo
internal/
  core/          engine, tool dispatch, handlers, egress proxy, scope, sandbox
  reviewer/      adversarial multi-model panel + aggregation
  director/      "new horizon" hypothesis generation when stuck
  precheck/      deterministic pre-filter
  llm/           OpenAI-compatible chat + embedding clients
  storage/       MongoDB (findings, reviews, outcomes, lessons, transcripts …)
  types/         finding lifecycle, panel verdicts, outcomes, lessons
  workspace/     per-program filesystem workspace + venv
  config/        yaml + .env loader
```

---

## Security tooling

The engine can call ~150 CLI security tools grouped by phase (recon, web scanning,
network, cloud, mobile, secrets, OPSEC), installed and audited via:

```bash
./scripts/install_tools.sh --all       # everything
./scripts/install_tools.sh --essentials
./scripts/check_tools.sh               # audit what's actually working
```

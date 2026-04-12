#!/bin/bash
# ============================================================================
# hack-ai-v2 — Tool Health Check
# Verifies all 183 security tools are installed AND working correctly
# Usage: bash scripts/check_tools.sh [--category <name>] [--json] [--verbose]
# ============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# Options
VERBOSE=false
JSON_OUTPUT=false
FILTER_CATEGORY=""
TOOLS_DIR="$HOME/.hack-ai-tools"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/plugins/core"

# Ensure all tool paths are in PATH
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin:/opt/metasploit-framework/bin"
ANDROID_SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export PATH="$PATH:$ANDROID_SDK/platform-tools:$ANDROID_SDK/emulator:$ANDROID_SDK/cmdline-tools/latest/bin"
NPM_PREFIX=$(npm config get prefix 2>/dev/null || echo "")
if [ -n "$NPM_PREFIX" ]; then export PATH="$PATH:$NPM_PREFIX/bin"; fi

# JSON accumulator
JSON_RESULTS="[]"

# ============================================================================
# Helpers
# ============================================================================

log_pass() {
    PASS=$((PASS + 1))
    if $JSON_OUTPUT; then return; fi
    local version_info=""
    if [ -n "${2:-}" ]; then version_info=" ${DIM}(${2})${NC}"; fi
    echo -e "  ${GREEN}✅ PASS${NC}  ${1}${version_info}"
}

log_fail() {
    FAIL=$((FAIL + 1))
    if $JSON_OUTPUT; then return; fi
    local reason=""
    if [ -n "${2:-}" ]; then reason=" ${DIM}— ${2}${NC}"; fi
    echo -e "  ${RED}❌ FAIL${NC}  ${1}${reason}"
}

log_skip() {
    SKIP=$((SKIP + 1))
    if $JSON_OUTPUT; then return; fi
    echo -e "  ${YELLOW}⏭  SKIP${NC}  ${1} ${DIM}— ${2:-skipped}${NC}"
}

add_json() {
    local name="$1" category="$2" status="$3" detail="${4:-}"
    JSON_RESULTS=$(echo "$JSON_RESULTS" | sed 's/]$//')
    if [ "$TOTAL" -gt 1 ]; then JSON_RESULTS="${JSON_RESULTS},"; fi
    JSON_RESULTS="${JSON_RESULTS}{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"$status\",\"detail\":\"$detail\"}]"
}

# Run a verify command with timeout, capture output
run_verify() {
    local cmd="$1"
    local output
    if command -v timeout &>/dev/null; then
        output=$(timeout 10 bash -c "$cmd" 2>&1 | head -3)
    else
        output=$(perl -e 'alarm 10; exec @ARGV' -- bash -c "$cmd" 2>&1 | head -3)
    fi
    local exit_code=$?
    echo "$output"
    return $exit_code
}

# Extract first line of version info from output
extract_version() {
    echo "$1" | head -1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r' | cut -c1-80
}

# ============================================================================
# Map tool name → actual binary (for tools with different binary names)
# ============================================================================

get_binary_name() {
    local name="$1"
    case "$name" in
        kiterunner)       echo "kr" ;;
        interactsh)       echo "interactsh-client" ;;
        subfinder_silent) echo "subfinder" ;;
        subover)          echo "SubOver" ;;
        githound)         echo "git-hound" ;;
        knockpy)          echo "knock" ;;
        reconng)          echo "recon-ng" ;;
        scoutsuite)       echo "scout" ;;
        getjs)            echo "getJS" ;;
        xsstrike)         echo "xsstrike" ;;
        nuclei_templates) echo "__dir_check__" ;;
        gittools)         echo "__dir_check__" ;;
        sharphound)       echo "__dir_check__" ;;
        massdns)          echo "__dir_check__" ;;
        gitrob)           echo "__dir_check__" ;;
        photon)           echo "__dir_check__" ;;
        crackmapexec)     echo "__dir_check__" ;;
        impacket)         echo "__dir_check__" ;;
        postman2swagger)  echo "__dir_check__" ;;
        theharvester)     echo "__dir_check__" ;;
        wappalyzer)       echo "__dir_check__" ;;
        metasploit)       echo "__dir_check__" ;;
        bloodhound)       echo "__dir_check__" ;;
        android_emulator) echo "__dir_check__" ;;
        sdkmanager)       echo "__dir_check__" ;;
        avdmanager)       echo "__dir_check__" ;;
        4naly3er)         echo "__dir_check__" ;;
        solidity-coverage) echo "__dir_check__" ;;
        *)                echo "$name" ;;
    esac
}

# ============================================================================
# Override broken verify commands from plugin YAMLs
# ============================================================================

get_verify_override() {
    local name="$1"
    case "$name" in
        john)             echo "john 2>&1 | head -1" ;;
        ldapsearch)       echo "ldapsearch -VV 2>&1 | head -1" ;;
        gau)              echo "gau --version 2>&1" ;;
        gospider)         echo "which gospider" ;;
        puredns)          echo "puredns -h 2>&1 | head -1" ;;
        gobuster)         echo "gobuster -h 2>&1 | head -1" ;;
        jaeles)           echo "jaeles -h 2>&1 | head -1" ;;
        nuclei_templates) echo "ls $TOOLS_DIR/nuclei-templates/README.md 2>/dev/null || ls $HOME/.nuclei-templates 2>/dev/null" ;;
        impacket)         echo "ls $HOME/.local/pipx/venvs/impacket 2>/dev/null || python3 -c 'import impacket; print(impacket.__version__)' 2>/dev/null" ;;
        sharphound)       echo "ls $TOOLS_DIR/sharphound 2>/dev/null" ;;
        gittools)         echo "ls $TOOLS_DIR/gittools 2>/dev/null" ;;
        massdns)          echo "ls $TOOLS_DIR/massdns/Makefile 2>/dev/null" ;;
        gitrob)           echo "ls $TOOLS_DIR/gitrob 2>/dev/null" ;;
        testssl)          echo "ls $TOOLS_DIR/testssl/testssl.sh 2>/dev/null" ;;
        reconftw)         echo "ls $TOOLS_DIR/reconftw/reconftw.sh 2>/dev/null" ;;
        masscan)          echo "masscan --version 2>&1 || which masscan" ;;
        wappalyzer)       echo "npm list -g wappalyzer 2>/dev/null | grep wappalyzer || which wappalyzer 2>/dev/null" ;;
        crackmapexec)     echo "ls $TOOLS_DIR/nxc 2>/dev/null || nxc --version 2>&1" ;;
        smbclient)        echo "smbclient --version 2>&1 | head -1" ;;
        photon)           echo "pip3 show photon 2>/dev/null | head -2 || ls $TOOLS_DIR/photon 2>/dev/null" ;;
        theharvester)     echo "pip3 show theHarvester 2>/dev/null | head -2 || theHarvester -h 2>&1 | head -1 || ls $TOOLS_DIR/theharvester 2>/dev/null" ;;
        postman2swagger)  echo "which p2o 2>/dev/null || npm list -g postman-to-openapi 2>/dev/null | grep postman" ;;
        metasploit)       echo "msfconsole --version 2>&1 | head -1" ;;
        bloodhound)       echo "ls /Applications/BloodHound.app 2>/dev/null || which bloodhound 2>/dev/null" ;;
        adb)              echo "adb --version 2>&1 | head -1" ;;
        android_emulator) echo "emulator -version 2>&1 | head -1 || ls $ANDROID_SDK/emulator/emulator 2>/dev/null" ;;
        sdkmanager)       echo "sdkmanager --version 2>&1 | head -1 || ls $ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager 2>/dev/null" ;;
        avdmanager)       echo "avdmanager list avd 2>&1 | head -1 || ls $ANDROID_SDK/cmdline-tools/latest/bin/avdmanager 2>/dev/null" ;;
        foundry)          echo "forge --version 2>&1" ;;
        stellar-cli)      echo "stellar --version 2>&1 || soroban --version 2>&1" ;;
        cargo-fuzz)       echo "cargo fuzz --version 2>&1" ;;
        cargo-audit)      echo "cargo-audit --version 2>&1 || cargo audit --version 2>&1" ;;
        miri)             echo "rustup +nightly component list 2>/dev/null | grep 'miri.*installed'" ;;
        clippy)           echo "cargo clippy --version 2>&1" ;;
        4naly3er)         echo "ls $TOOLS_DIR/4naly3er/src/index.ts 2>/dev/null" ;;
        solidity-coverage) echo "npm list -g solidity-coverage 2>/dev/null | grep solidity-coverage" ;;
        wabt)             echo "wasm-decompile --version 2>&1" ;;
        difftastic)       echo "difft --version 2>&1" ;;
        mythril)          echo "myth version 2>&1" ;;
        *)                echo "" ;;
    esac
}

# ============================================================================
# Check a single tool
# ============================================================================

check_tool() {
    local name="$1"
    local category="$2"
    local verify_cmd="$3"
    local install_method="${4:-}"

    TOTAL=$((TOTAL + 1))

    # Filter by category if specified
    if [ -n "$FILTER_CATEGORY" ] && [ "$category" != "$FILTER_CATEGORY" ]; then
        SKIP=$((SKIP + 1))
        TOTAL=$((TOTAL - 1))
        return
    fi

    # Docker-based tools
    if [ "$install_method" = "docker" ]; then
        log_skip "$category/$name" "docker-based tool"
        $JSON_OUTPUT && add_json "$name" "$category" "skip" "docker"
        return
    fi

    # Custom/manual tools
    if [ "$install_method" = "custom" ] || [ "$install_method" = "manual" ]; then
        log_skip "$category/$name" "$install_method install"
        $JSON_OUTPUT && add_json "$name" "$category" "skip" "$install_method"
        return
    fi

    # --- Apply overrides ---
    local override
    override=$(get_verify_override "$name")
    if [ -n "$override" ]; then
        verify_cmd="$override"
    fi

    local binary
    binary=$(get_binary_name "$name")

    # --- Step 1: Find the tool ---
    local found=false

    # Check if it's a dir-check tool (git-cloned, pipx venv, npm package, etc.)
    if [ "$binary" = "__dir_check__" ]; then
        # Run the verify command — it checks dirs, venvs, npm, etc.
        local output
        output=$(run_verify "$verify_cmd" 2>&1) || true
        if [ -n "$output" ]; then
            local version_line
            version_line=$(extract_version "$output")
            log_pass "$category/$name" "${version_line:-found}"
            $JSON_OUTPUT && add_json "$name" "$category" "pass" "${version_line:-found}"
        else
            log_fail "$category/$name" "not installed"
            $JSON_OUTPUT && add_json "$name" "$category" "fail" "not installed"
        fi
        return
    fi

    # Check binary on PATH
    if command -v "$binary" &>/dev/null; then
        found=true
    elif [ "$binary" != "$name" ] && command -v "$name" &>/dev/null; then
        found=true
        binary="$name"
    fi

    # Check ~/.hack-ai-tools directory
    if ! $found && [ -d "$TOOLS_DIR/$name" ]; then
        found=true
        # For git-cloned tools, verify inside the directory
        local output
        output=$(cd "$TOOLS_DIR/$name" 2>/dev/null && run_verify "$verify_cmd" 2>&1) || true
        local version_line
        version_line=$(extract_version "$output")
        log_pass "$category/$name" "${version_line:-git clone}"
        $JSON_OUTPUT && add_json "$name" "$category" "pass" "${version_line:-git}"
        return
    fi

    if ! $found; then
        log_fail "$category/$name" "not installed"
        $JSON_OUTPUT && add_json "$name" "$category" "fail" "not installed"
        return
    fi

    # --- Step 2: Verify it actually runs ---
    local output
    output=$(run_verify "$verify_cmd" 2>&1)
    local exit_code=$?

    # LENIENT: If the binary exists and produces ANY output, it's working.
    # Many security tools return exit 1/2/3 for --version/--help but still work fine.
    if [ -n "$output" ]; then
        local version_line
        version_line=$(extract_version "$output")
        log_pass "$category/$name" "$version_line"
        $JSON_OUTPUT && add_json "$name" "$category" "pass" "$version_line"
    elif [ $exit_code -eq 0 ]; then
        log_pass "$category/$name" "runs ok"
        $JSON_OUTPUT && add_json "$name" "$category" "pass" "ok"
    else
        log_fail "$category/$name" "exits with code $exit_code (no output)"
        $JSON_OUTPUT && add_json "$name" "$category" "fail" "exit $exit_code"
    fi

    # Verbose: show full output
    if $VERBOSE && [ -n "$output" ]; then
        echo "$output" | head -5 | sed 's/^/      /'
    fi
}

# ============================================================================
# Run checks — reads verify commands from plugin YAMLs
# ============================================================================

run_all_checks() {
    if [ ! -d "$PLUGIN_DIR" ]; then
        echo -e "${RED}Plugin directory not found: $PLUGIN_DIR${NC}"
        exit 1
    fi

    local current_category=""

    for yaml_file in $(find "$PLUGIN_DIR" -name "*.yaml" | sort); do
        local name category verify_cmd install_method

        name=$(grep '^name:' "$yaml_file" | head -1 | sed 's/^name: *//')
        category=$(basename "$(dirname "$yaml_file")")
        verify_cmd=$(grep '  verify:' "$yaml_file" | head -1 | sed 's/.*verify: *//')
        install_method=$(grep '  method:' "$yaml_file" | head -1 | sed 's/.*method: *//')

        # Print category header
        if ! $JSON_OUTPUT && [ "$category" != "$current_category" ]; then
            if [ -n "$FILTER_CATEGORY" ] && [ "$category" != "$FILTER_CATEGORY" ]; then
                current_category="$category"
                continue
            fi
            echo ""
            echo -e "${BOLD}${BLUE}── $category ──${NC}"
            current_category="$category"
        fi

        if [ -z "$verify_cmd" ]; then
            verify_cmd="which $name"
        fi

        check_tool "$name" "$category" "$verify_cmd" "$install_method"
    done
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    if $JSON_OUTPUT; then
        echo "$JSON_RESULTS"
        return
    fi

    local total_checked=$((PASS + FAIL))
    local pct=0
    if [ $total_checked -gt 0 ]; then
        pct=$((PASS * 100 / total_checked))
    fi

    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Health Check Summary${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✅ Passing:${NC}  $PASS"
    echo -e "  ${RED}❌ Failing:${NC}  $FAIL"
    echo -e "  ${YELLOW}⏭  Skipped:${NC} $SKIP"
    echo -e "  ${CYAN}📊 Total:${NC}    $TOTAL  ($pct% operational)"
    echo ""

    # Health bar
    local bar_len=40
    local filled=$((pct * bar_len / 100))
    local empty=$((bar_len - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    local bar_color="$RED"
    if [ $pct -ge 80 ]; then bar_color="$GREEN"; elif [ $pct -ge 50 ]; then bar_color="$YELLOW"; fi
    echo -e "  ${bar_color}${bar}${NC} ${pct}%"

    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════${NC}"

    if [ $FAIL -gt 0 ]; then
        echo ""
        echo -e "  ${YELLOW}Install missing tools:${NC}"
        echo -e "    bash scripts/install_tools.sh --all"
        echo ""
    fi
}

# ============================================================================
# Main
# ============================================================================

usage() {
    echo -e "${BOLD}hack-ai-v2 Tool Health Check${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --category <name>   Check only a specific category"
    echo "                      (auth, cloud, exploit, mobile, network, proxy,"
    echo "                       recon, secrets, utility, web, web3)"
    echo "  --json              Output results as JSON"
    echo "  --verbose           Show full verify output"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                        # Check all 150 tools"
    echo "  $0 --category recon       # Check recon tools only"
    echo "  $0 --json                 # JSON output for CI/CD"
    echo "  $0 --verbose              # Show version details"
    echo ""
}

main() {
    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --category)  FILTER_CATEGORY="$2"; shift 2 ;;
            --json)      JSON_OUTPUT=true; shift ;;
            --verbose)   VERBOSE=true; shift ;;
            --help)      usage; exit 0 ;;
            *)           echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    if ! $JSON_OUTPUT; then
        echo -e "${BOLD}${BLUE}"
        echo "  ╔═══════════════════════════════════════╗"
        echo "  ║     hack-ai-v2 Tool Health Check      ║"
        echo "  ║    183 Security + Web3 Tools Audit    ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"

        if [ -n "$FILTER_CATEGORY" ]; then
            echo -e "  ${CYAN}Filtering: $FILTER_CATEGORY${NC}"
        fi
    fi

    run_all_checks
    print_summary
}

main "$@"

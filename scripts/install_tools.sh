#!/bin/bash
# ============================================================================
# hack-ai-v2 — Complete Tool Installer
# Installs ALL 183 security tools defined in plugins/core/*.yaml
# Usage: bash scripts/install_tools.sh [--all|--go|--python|--system|--git|--rust|--web3|--opsec|--essentials|--check]
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
INSTALLED=0
FAILED=0
SKIPPED=0
TOTAL=0

# Directories
TOOLS_DIR="$HOME/.hack-ai-tools"
WORDLISTS_DIR="$HOME/.hack-ai-wordlists"
BIN_DIR="$HOME/.local/bin"

# Detect OS
OS=$(uname -s)

# ============================================================================
# Helpers
# ============================================================================

log_header() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${BLUE}  $1${NC}"; echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"; }
log_install() { echo -e "  ${CYAN}[INSTALL]${NC} $1"; }
log_ok()      { echo -e "  ${GREEN}[  OK  ]${NC} $1"; INSTALLED=$((INSTALLED + 1)); }
log_fail()    { echo -e "  ${RED}[ FAIL ]${NC} $1"; FAILED=$((FAILED + 1)); }
log_skip()    { echo -e "  ${YELLOW}[ SKIP ]${NC} $1"; SKIPPED=$((SKIPPED + 1)); }
log_exists()  { echo -e "  ${GREEN}[EXISTS]${NC} $1 → $(which "$1" 2>/dev/null || echo 'found')"; INSTALLED=$((INSTALLED + 1)); }

try_install() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    if command -v "$name" &>/dev/null; then
        log_exists "$name"
        return 0
    fi
    log_install "$name"
    if "$@" 2>/dev/null; then
        log_ok "$name"
    else
        log_fail "$name"
    fi
}

try_go_install() {
    local name="$1"
    local pkg="$2"
    TOTAL=$((TOTAL + 1))
    if command -v "$name" &>/dev/null; then
        log_exists "$name"
        return 0
    fi
    log_install "$name"
    if go install "$pkg" 2>/dev/null; then
        log_ok "$name"
    else
        log_fail "$name"
    fi
}

try_pip_install() {
    local name="$1"
    local pkg="$2"
    local git_fallback="${3:-}"
    TOTAL=$((TOTAL + 1))
    if command -v "$name" &>/dev/null; then
        log_exists "$name"
        return 0
    fi
    log_install "$name"
    # Try pipx first
    if command -v pipx &>/dev/null; then
        if pipx install "$pkg" 2>/dev/null; then
            log_ok "$name"
            return 0
        fi
    fi
    # Fallback: pip3 with --user
    if pip3 install "$pkg" --user --quiet --break-system-packages 2>/dev/null || pip3 install "$pkg" --user --quiet 2>/dev/null; then
        log_ok "$name (via pip3)"
        return 0
    fi
    # Final fallback: git clone
    if [ -n "$git_fallback" ]; then
        local target_dir="$TOOLS_DIR/$name"
        if [ -d "$target_dir" ]; then
            log_ok "$name (git exists)"
        elif git clone --quiet --depth 1 "$git_fallback" "$target_dir" 2>/dev/null; then
            cd "$target_dir" && (pip3 install -r requirements.txt --quiet --break-system-packages 2>/dev/null || pip3 install -r requirements.txt --quiet 2>/dev/null || true) && cd - >/dev/null
            log_ok "$name (via git)"
        else
            log_fail "$name"
        fi
    else
        log_fail "$name"
    fi
}

try_git_install() {
    local name="$1"
    local repo="$2"
    local post_install="${3:-}"
    TOTAL=$((TOTAL + 1))
    local target_dir="$TOOLS_DIR/$name"
    if [ -d "$target_dir" ]; then
        log_exists "$name (in $TOOLS_DIR)"
        return 0
    fi
    log_install "$name"
    if git clone --quiet --depth 1 "$repo" "$target_dir" 2>/dev/null; then
        if [ -n "$post_install" ]; then
            (cd "$target_dir" && eval "$post_install" 2>/dev/null) || true
        fi
        log_ok "$name → $target_dir"
    else
        log_fail "$name"
    fi
}

try_brew_install() {
    local name="$1"
    local pkg="${2:-$name}"
    TOTAL=$((TOTAL + 1))
    if command -v "$name" &>/dev/null; then
        log_exists "$name"
        return 0
    fi
    log_install "$name"
    if [ "$OS" == "Darwin" ] && command -v brew &>/dev/null; then
        if brew install "$pkg" 2>/dev/null; then
            log_ok "$name"
        else
            log_fail "$name"
        fi
    else
        if sudo apt-get install -y "$pkg" 2>/dev/null; then
            log_ok "$name"
        else
            log_fail "$name (need brew on macOS or apt on Linux)"
        fi
    fi
}

# ============================================================================
# GO TOOLS (52 tools)
# ============================================================================

install_go_tools() {
    log_header "Go Tools (52)"

    if ! command -v go &>/dev/null; then
        echo -e "  ${RED}Go not found! Install Go first: https://go.dev/dl/${NC}"
        return 1
    fi

    # === ProjectDiscovery Suite ===
    try_go_install subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    try_go_install httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    try_go_install nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    try_go_install katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
    try_go_install naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    try_go_install dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    try_go_install shuffledns   "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    try_go_install chaos        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    try_go_install notify       "github.com/projectdiscovery/notify/cmd/notify@latest"
    try_go_install uncover      "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    try_go_install tlsx         "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    try_go_install mapcidr      "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    try_go_install asnmap       "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    try_go_install kerbrute     "github.com/ropnop/kerbrute@latest"
    try_go_install alterx       "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    try_go_install cvemap       "github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
    try_go_install interactsh   "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

    # === tomnomnom Suite ===
    try_go_install waybackurls  "github.com/tomnomnom/waybackurls@latest"
    try_go_install assetfinder  "github.com/tomnomnom/assetfinder@latest"
    try_go_install httprobe     "github.com/tomnomnom/httprobe@latest"
    try_go_install unfurl       "github.com/tomnomnom/unfurl@latest"
    try_go_install anew         "github.com/tomnomnom/anew@latest"
    try_go_install qsreplace    "github.com/tomnomnom/qsreplace@latest"
    try_go_install gron         "github.com/tomnomnom/gron@latest"
    try_go_install meg          "github.com/tomnomnom/meg@latest"
    try_go_install gf           "github.com/tomnomnom/gf@latest"

    # === hakluke Suite ===
    try_go_install hakrawler    "github.com/hakluke/hakrawler@latest"
    try_go_install hakcheckurl  "github.com/hakluke/hakcheckurl@latest"
    try_go_install hakrevdns    "github.com/hakluke/hakrevdns@latest"

    # === Scanners & Fuzzers ===
    try_go_install dalfox       "github.com/hahwul/dalfox/v2@latest"
    try_go_install ffuf         "github.com/ffuf/ffuf/v2@latest"
    try_go_install gobuster     "github.com/OJ/gobuster/v3@latest"
    try_go_install jaeles       "github.com/jaeles-project/jaeles@latest"
    try_go_install gospider     "github.com/jaeles-project/gospider@latest"
    try_go_install crlfuzz      "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"

    # === Secrets ===
    try_go_install gitleaks     "github.com/gitleaks/gitleaks/v8@latest"
    try_go_install trufflehog   "github.com/trufflesecurity/trufflehog/v3@latest"
    try_go_install git-hound    "github.com/tillson/git-hound@latest"
    # gitrob is archived — install from git clone instead
    try_git_install gitrob "https://github.com/michenriksen/gitrob.git"

    # === Subdomain Takeover ===
    try_go_install subjack      "github.com/haccer/subjack@latest"
    try_go_install subover      "github.com/Ice3man543/SubOver@latest"
    try_go_install subzy        "github.com/PentestPad/subzy@latest"

    # === Other Recon ===
    try_go_install gau          "github.com/lc/gau/v2/cmd/gau@latest"
    try_go_install getjs        "github.com/003random/getJS@latest"
    try_go_install subjs        "github.com/lc/subjs@latest"
    try_go_install gotator      "github.com/Josue87/gotator@latest"
    try_go_install cariddi      "github.com/edoardottt/cariddi/cmd/cariddi@latest"
    try_go_install smap         "github.com/s0md3v/smap/cmd/smap@latest"
    # kiterunner build broken in modern Go — install from git clone
    try_git_install kiterunner "https://github.com/assetnote/kiterunner.git" "go build ./cmd/kr 2>/dev/null || true"
    try_go_install puredns      "github.com/d3mondev/puredns/v2@latest"
    try_go_install gowitness    "github.com/sensepost/gowitness@latest"

    # === Amass (separate — can be slow) ===
    try_go_install amass        "github.com/owasp-amass/amass/v4/...@master"
}

# ============================================================================
# PYTHON TOOLS (32 tools)
# ============================================================================

install_python_tools() {
    log_header "Python Tools (32)"

    if ! command -v pip3 &>/dev/null && ! command -v pipx &>/dev/null; then
        echo -e "  ${RED}pip3/pipx not found! Install Python first.${NC}"
        return 1
    fi

    # Install pipx if on macOS and not available
    if ! command -v pipx &>/dev/null && [ "$OS" == "Darwin" ] && command -v brew &>/dev/null; then
        log_install "pipx (package manager)"
        brew install pipx 2>/dev/null && pipx ensurepath 2>/dev/null || true
    fi

    # === Recon ===
    try_pip_install arjun         "arjun"
    try_pip_install paramspider   "paramspider"                   "https://github.com/devanshbatham/ParamSpider.git"
    try_pip_install knockpy       "knock"
    try_pip_install censys        "censys"
    try_pip_install shodan        "shodan"
    try_pip_install theharvester  "theHarvester"
    try_pip_install photon        "photon"                        "https://github.com/s0md3v/Photon.git"
    try_pip_install fierce        "fierce"
    try_pip_install dnsrecon      "dnsrecon"
    try_pip_install dnstwist      "dnstwist"
    try_pip_install dnsgen        "dnsgen"
    try_pip_install altdns        "py-altdns"
    try_pip_install reconng       "recon-ng"                      "https://github.com/lanmaster53/recon-ng.git"
    try_pip_install spiderfoot    "spiderfoot"                    "https://github.com/smicallef/spiderfoot.git"
    try_pip_install wafw00f       "wafw00f"

    # === Web Scanning ===
    try_pip_install sqlmap        "sqlmap"
    try_pip_install dirsearch     "dirsearch"
    try_pip_install wfuzz         "wfuzz"                         "https://github.com/xmendez/wfuzz.git"
    try_pip_install ghauri        "ghauri"                        "https://github.com/r0oth3x49/ghauri.git"
    try_pip_install droopescan    "droopescan"
    try_pip_install xsstrike      "XSStrike"
    try_pip_install openredirex   "openredirex"                   "https://github.com/devanshbatham/OpenRedireX.git"
    try_pip_install subdominator  "subdominator"

    # === Network ===
    # crackmapexec is now netexec (successor project)
    try_pip_install nxc            "netexec"                      "https://github.com/Pennyw0rth/NetExec.git"
    try_pip_install impacket      "impacket"
    try_pip_install smbmap        "smbmap"
    try_pip_install sslyze        "sslyze"
    try_pip_install mitmproxy     "mitmproxy"

    # === Mobile ===
    try_pip_install frida         "frida-tools"
    try_pip_install objection     "objection"
    try_pip_install drozer        "drozer"

    # === Utility ===
    try_pip_install uro           "uro"

    # === Cloud ===
    try_pip_install s3scanner     "s3scanner"
    try_pip_install prowler       "prowler"
    try_pip_install scoutsuite    "scoutsuite"

    # === Additional tools from plugins ===
    try_pip_install jwt_tool      "jwt_tool"                      "https://github.com/ticarpi/jwt_tool.git"
    try_pip_install cloudenum     "cloud_enum"                    "https://github.com/initstring/cloud_enum.git"
}

# ============================================================================
# SYSTEM TOOLS (via Homebrew on macOS, apt on Linux) — 20 tools
# ============================================================================

install_system_tools() {
    log_header "System Tools (20)"

    # === Network/Scanning ===
    try_brew_install nmap
    try_brew_install nikto
    try_brew_install masscan
    try_brew_install naabu        # Also available via Go
    try_brew_install sslscan

    # === Auth/Cracking ===
    try_brew_install hydra
    try_brew_install john         "john-jumbo"
    try_brew_install hashcat

    # === Network Utils ===
    try_brew_install tcpdump
    try_brew_install tshark       "wireshark"
    try_brew_install socat
    try_brew_install netcat       "nmap"          # ncat comes with nmap
    try_brew_install smbclient    "samba"
    try_brew_install tor

    # === Content/CMS ===
    # whatweb and cewl are not in Homebrew — use git clone
    try_git_install whatweb "https://github.com/urbanadventurer/WhatWeb.git"
    try_git_install cewl "https://github.com/digininja/CeWL.git" "gem install bundler 2>/dev/null && bundle install 2>/dev/null || true"
    try_brew_install crunch

    # === Misc ===
    try_brew_install jq
    try_brew_install jadx
    try_brew_install apktool
    try_brew_install ipatool

    # === Mobile (macOS) ===
    if [ "$OS" == "Darwin" ]; then
        try_brew_install findomain
    fi

    # === Exploit/AD Tools ===
    TOTAL=$((TOTAL + 1))
    if command -v msfconsole &>/dev/null; then
        log_exists "metasploit"
    else
        log_install "metasploit"
        # Use official Rapid7 installer (brew cask is deprecated/broken)
        local msfinstall_tmp="/tmp/msfinstall"
        if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o "$msfinstall_tmp" 2>/dev/null && \
           chmod 755 "$msfinstall_tmp" && \
           "$msfinstall_tmp" 2>/dev/null; then
            log_ok "metasploit (via rapid7 installer)"
            rm -f "$msfinstall_tmp"
        else
            rm -f "$msfinstall_tmp"
            log_fail "metasploit — run manually: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall"
        fi
    fi

    TOTAL=$((TOTAL + 1))
    if [ -d "/Applications/BloodHound.app" ] || command -v bloodhound &>/dev/null; then
        log_exists "bloodhound"
    else
        log_install "bloodhound"
        if command -v brew &>/dev/null && brew install --cask bloodhound 2>/dev/null; then
            log_ok "bloodhound (via brew cask)"
        else
            log_fail "bloodhound"
        fi
    fi

    # === Android SDK / Emulator Tools ===
    local ANDROID_SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
    local SDK_PATHS="$ANDROID_SDK/platform-tools:$ANDROID_SDK/emulator:$ANDROID_SDK/cmdline-tools/latest/bin"
    export PATH="$PATH:$SDK_PATHS"

    # adb
    TOTAL=$((TOTAL + 1))
    if command -v adb &>/dev/null; then
        log_exists "adb"
    else
        log_install "adb"
        if command -v brew &>/dev/null && brew install android-platform-tools 2>/dev/null; then
            log_ok "adb (via brew)"
        else
            log_fail "adb — install Android SDK or: brew install android-platform-tools"
        fi
    fi

    # emulator
    TOTAL=$((TOTAL + 1))
    if command -v emulator &>/dev/null || [ -f "$ANDROID_SDK/emulator/emulator" ]; then
        log_exists "android_emulator"
    else
        log_install "android_emulator"
        if command -v sdkmanager &>/dev/null || [ -f "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
            if "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" --install "emulator" 2>/dev/null; then
                log_ok "android_emulator (via sdkmanager)"
            else
                log_fail "android_emulator — run: sdkmanager --install emulator"
            fi
        else
            log_fail "android_emulator — install Android SDK first"
        fi
    fi

    # sdkmanager
    TOTAL=$((TOTAL + 1))
    if command -v sdkmanager &>/dev/null || [ -f "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
        log_exists "sdkmanager"
    else
        log_install "sdkmanager"
        if command -v brew &>/dev/null && brew install --cask android-commandlinetools 2>/dev/null; then
            log_ok "sdkmanager (via brew cask)"
        else
            log_fail "sdkmanager — install Android Studio or: brew install --cask android-commandlinetools"
        fi
    fi

    # avdmanager
    TOTAL=$((TOTAL + 1))
    if command -v avdmanager &>/dev/null || [ -f "$ANDROID_SDK/cmdline-tools/latest/bin/avdmanager" ]; then
        log_exists "avdmanager"
    else
        log_install "avdmanager"
        if command -v sdkmanager &>/dev/null || [ -f "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
            if "$ANDROID_SDK/cmdline-tools/latest/bin/sdkmanager" --install "cmdline-tools;latest" 2>/dev/null; then
                log_ok "avdmanager (via sdkmanager)"
            else
                log_fail "avdmanager"
            fi
        else
            log_fail "avdmanager — install Android SDK first"
        fi
    fi
}

# ============================================================================
# GIT-BASED TOOLS (22 tools) — cloned to ~/.hack-ai-tools/
# ============================================================================

install_git_tools() {
    log_header "Git-Based Tools (22) → $TOOLS_DIR"
    mkdir -p "$TOOLS_DIR"

    # === Web Exploitation ===
    try_git_install bypass403     "https://github.com/iamj0ker/bypass-403.git"
    try_git_install cmsmap        "https://github.com/Dionach/CMSmap.git"
    try_git_install commix        "https://github.com/commixproject/commix.git"
    try_git_install corsy         "https://github.com/s0md3v/Corsy.git"             "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install graphqlmap    "https://github.com/swisskyrepo/GraphQLmap.git"    "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install joomscan      "https://github.com/OWASP/joomscan.git"
    try_git_install lfisuite      "https://github.com/D35m0nd142/LFISuite.git"
    try_git_install nosqlmap      "https://github.com/codingo/NoSQLMap.git"          "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install shcheck       "https://github.com/santoru/shcheck.git"
    try_git_install smuggler      "https://github.com/defparam/smuggler.git"
    try_git_install ssrfmap       "https://github.com/swisskyrepo/SSRFmap.git"       "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install tplmap        "https://github.com/epinna/tplmap.git"             "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install xxeinjector   "https://github.com/enjoiz/XXEinjector.git"

    # === Recon ===
    try_git_install eyewitness    "https://github.com/RedSiege/EyeWitness.git"
    try_git_install finalrecon    "https://github.com/thewhiteh4t/FinalRecon.git"    "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install linkfinder    "https://github.com/GerbenJavado/LinkFinder.git"   "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install massdns       "https://github.com/blechschmidt/massdns.git"      "make 2>/dev/null || true"
    try_git_install oneforall     "https://github.com/shmilylty/OneForAll.git"       "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install reconftw      "https://github.com/six2dez/reconftw.git"
    try_git_install sublist3r     "https://github.com/aboul3la/Sublist3r.git"        "pip3 install -r requirements.txt --quiet 2>/dev/null || true"

    # === Secrets ===
    try_git_install secretfinder  "https://github.com/m4ll0k/SecretFinder.git"       "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install gitdorker     "https://github.com/obheda12/GitDorker.git"        "pip3 install -r requirements.txt --quiet 2>/dev/null || true"
    try_git_install gittools      "https://github.com/internetwache/GitTools.git"

    # === Utility ===
    try_git_install cupp          "https://github.com/Mebus/cupp.git"
    try_git_install sharphound    "https://github.com/BloodHoundAD/SharpHound.git"
    try_git_install testssl       "https://github.com/drwetter/testssl.sh.git"
    try_git_install enum4linux    "https://github.com/CiscoCXSecurity/enum4linux.git"
    try_git_install responder     "https://github.com/lgandx/Responder.git"
    try_git_install searchsploit  "https://gitlab.com/exploit-database/exploitdb.git"

    # === Nuclei Templates ===
    try_git_install nuclei-templates "https://github.com/projectdiscovery/nuclei-templates.git"
}

# ============================================================================
# RUST TOOLS (3 tools)
# ============================================================================

install_rust_tools() {
    log_header "Rust Tools (4)"

    if ! command -v cargo &>/dev/null; then
        echo -e "  ${YELLOW}Cargo not found. Attempting brew install...${NC}"
        if [ "$OS" == "Darwin" ] && command -v brew &>/dev/null; then
            brew install rust 2>/dev/null || true
        fi
    fi

    if command -v cargo &>/dev/null; then
        TOTAL=$((TOTAL + 1))
        if command -v feroxbuster &>/dev/null; then log_exists "feroxbuster"; else
            log_install "feroxbuster"
            cargo install feroxbuster 2>/dev/null && log_ok "feroxbuster" || log_fail "feroxbuster"
        fi

        TOTAL=$((TOTAL + 1))
        if command -v rustscan &>/dev/null; then log_exists "rustscan"; else
            log_install "rustscan"
            cargo install rustscan 2>/dev/null && log_ok "rustscan" || log_fail "rustscan"
        fi

        TOTAL=$((TOTAL + 1))
        if command -v x8 &>/dev/null; then log_exists "x8"; else
            log_install "x8"
            cargo install x8 2>/dev/null && log_ok "x8" || log_fail "x8"
        fi

        TOTAL=$((TOTAL + 1))
        if command -v apkeep &>/dev/null; then log_exists "apkeep"; else
            log_install "apkeep"
            cargo install apkeep 2>/dev/null && log_ok "apkeep" || log_fail "apkeep"
        fi
    else
        echo -e "  ${RED}Cargo still not available. Skipping Rust tools.${NC}"
        SKIPPED=$((SKIPPED + 3))
        TOTAL=$((TOTAL + 3))
    fi
}

# ============================================================================
# NPM TOOLS (2 tools)
# ============================================================================

install_npm_tools() {
    log_header "NPM Tools (2)"

    if ! command -v npm &>/dev/null; then
        echo -e "  ${YELLOW}npm not found. Attempting brew install...${NC}"
        if [ "$OS" == "Darwin" ] && command -v brew &>/dev/null; then
            brew install node 2>/dev/null || true
        fi
    fi

    if command -v npm &>/dev/null; then
        TOTAL=$((TOTAL + 1))
        if command -v wappalyzer &>/dev/null; then log_exists "wappalyzer"; else
            log_install "wappalyzer"
            npm install -g wappalyzer 2>/dev/null && log_ok "wappalyzer" || log_fail "wappalyzer"
        fi

        TOTAL=$((TOTAL + 1))
        if command -v p2o &>/dev/null; then log_exists "postman2swagger"; else
            log_install "postman2swagger"
            npm install -g postman-to-openapi 2>/dev/null && log_ok "postman2swagger" || log_fail "postman2swagger"
        fi
    else
        echo -e "  ${RED}npm still not available. Skipping NPM tools.${NC}"
        SKIPPED=$((SKIPPED + 2))
        TOTAL=$((TOTAL + 2))
    fi
}

# ============================================================================
# RUBY TOOLS (1 tool)
# ============================================================================

install_ruby_tools() {
    log_header "Ruby Tools (1)"

    TOTAL=$((TOTAL + 1))
    if command -v wpscan &>/dev/null; then
        log_exists "wpscan"
    else
        log_install "wpscan"
        # Try brew tap first (most reliable on macOS)
        if [ "$OS" == "Darwin" ] && command -v brew &>/dev/null; then
            if brew install wpscanteam/tap/wpscan 2>/dev/null; then
                # Fix post-install using brew's own ruby
                local brew_ruby="$(brew --prefix)/opt/ruby/bin/ruby"
                if [ -x "$brew_ruby" ]; then
                    RUBY="$brew_ruby" brew postinstall wpscanteam/tap/wpscan 2>/dev/null || true
                fi
                log_ok "wpscan (via brew tap)"
                return
            fi
        fi
        # Fallback: gem install
        if command -v gem &>/dev/null; then
            gem install wpscan --no-document 2>/dev/null && log_ok "wpscan" || log_fail "wpscan"
        else
            log_fail "wpscan"
        fi
    fi
}

# ============================================================================
# BINARY DOWNLOADS (1 tool)
# ============================================================================

install_binary_tools() {
    log_header "Binary Downloads (1)"
    mkdir -p "$BIN_DIR"

    TOTAL=$((TOTAL + 1))
    if command -v findomain &>/dev/null; then
        log_exists "findomain"
    else
        log_install "findomain"
        if [ "$OS" == "Darwin" ]; then
            # Try brew first on macOS
            if command -v brew &>/dev/null; then
                brew install findomain 2>/dev/null && log_ok "findomain" || log_fail "findomain"
            else
                curl -sL "https://github.com/findomain/findomain/releases/latest/download/findomain-osx" -o "$BIN_DIR/findomain" && chmod +x "$BIN_DIR/findomain" && log_ok "findomain" || log_fail "findomain"
            fi
        else
            curl -sL "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" -o "$BIN_DIR/findomain" && chmod +x "$BIN_DIR/findomain" && log_ok "findomain" || log_fail "findomain"
        fi
    fi
}

# ============================================================================
# OPSEC / ANONYMIZATION TOOLS (4 tools)
# ============================================================================

install_opsec_tools() {
    log_header "OPSEC / Anonymization Tools (4)"

    # === ProtonVPN CLI — Free VPN with country selection ===
    TOTAL=$((TOTAL + 1))
    if command -v protonvpn-cli &>/dev/null || command -v protonvpn &>/dev/null; then
        log_exists "protonvpn-cli"
    else
        log_install "protonvpn-cli"
        if command -v pipx &>/dev/null; then
            pipx install protonvpn-cli 2>/dev/null && log_ok "protonvpn-cli (via pipx)" || {
                pip3 install protonvpn-cli --user --quiet --break-system-packages 2>/dev/null || \
                pip3 install protonvpn-cli --user --quiet 2>/dev/null && \
                log_ok "protonvpn-cli (via pip3)" || log_fail "protonvpn-cli"
            }
        else
            pip3 install protonvpn-cli --user --quiet --break-system-packages 2>/dev/null || \
            pip3 install protonvpn-cli --user --quiet 2>/dev/null && \
            log_ok "protonvpn-cli (via pip3)" || log_fail "protonvpn-cli"
        fi
    fi

    # === proxychains-ng — Route any tool through proxy chains ===
    TOTAL=$((TOTAL + 1))
    if command -v proxychains4 &>/dev/null || command -v proxychains &>/dev/null; then
        log_exists "proxychains4"
    else
        log_install "proxychains-ng"
        if [ "$OS" == "Darwin" ] && command -v brew &>/dev/null; then
            brew install proxychains-ng 2>/dev/null && log_ok "proxychains-ng" || log_fail "proxychains-ng"
        else
            sudo apt-get install -y proxychains4 2>/dev/null && log_ok "proxychains4" || log_fail "proxychains-ng"
        fi
    fi

    # === SpoofMAC — MAC address spoofing (macOS + Linux) ===
    try_pip_install spoof-mac "SpoofMAC" "https://github.com/feross/SpoofMAC.git"

    # === macchanger — MAC address changer (Linux only) ===
    TOTAL=$((TOTAL + 1))
    if [ "$OS" == "Linux" ]; then
        if command -v macchanger &>/dev/null; then
            log_exists "macchanger"
        else
            log_install "macchanger"
            sudo apt-get install -y macchanger 2>/dev/null && log_ok "macchanger" || log_fail "macchanger"
        fi
    else
        log_skip "macchanger (Linux-only, skipped on macOS — use SpoofMAC instead)"
    fi

    echo ""
    echo -e "  ${CYAN}ProtonVPN quickstart:${NC}"
    echo -e "    protonvpn-cli login <username>"
    echo -e "    protonvpn-cli connect --cc US    # Connect to US server"
    echo -e "    protonvpn-cli connect --cc DE    # Connect to Germany"
    echo -e "    protonvpn-cli disconnect"
}

# ============================================================================
# WEB3 / SMART CONTRACT AUDITING TOOLS (25 tools)
# ============================================================================

install_web3_tools() {
    log_header "Web3 Smart Contract Arsenal (25)"

    # ── EVM & Solidity (Moonwell, Compound forks) ────────────────────────

    # === Foundry (forge, cast, anvil, chisel) ===
    TOTAL=$((TOTAL + 1))
    if command -v forge &>/dev/null; then
        log_exists "foundry (forge)"
    else
        log_install "foundry (forge, cast, anvil, chisel)"
        if command -v brew &>/dev/null && brew install foundry 2>/dev/null; then
            log_ok "foundry (via brew)"
        elif curl -L https://foundry.paradigm.xyz 2>/dev/null | bash 2>/dev/null && \
             "$HOME/.foundry/bin/foundryup" 2>/dev/null; then
            log_ok "foundry (via foundryup)"
        else
            log_fail "foundry — run: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        fi
    fi

    # === Slither — Static Analysis ===
    try_pip_install slither "slither-analyzer"

    # === solc-select — Solidity version manager (required by Slither) ===
    try_pip_install solc-select "solc-select"

    # === Echidna — Property-Based Fuzzer ===
    try_brew_install echidna

    # === Medusa — Parallel Fuzzer ===
    try_brew_install medusa

    # === Halmos — Formal Verification ===
    try_pip_install halmos "halmos"

    # === Mythril — Symbolic Execution ===
    # Mythril has heavy C deps (z3-solver) — try pipx first, then brew
    TOTAL=$((TOTAL + 1))
    if command -v myth &>/dev/null; then
        log_exists "mythril (myth)"
    else
        log_install "mythril"
        if command -v pipx &>/dev/null && pipx install mythril 2>/dev/null; then
            log_ok "mythril (via pipx)"
        elif pip3 install mythril --user --quiet --break-system-packages 2>/dev/null; then
            log_ok "mythril (via pip3)"
        elif command -v brew &>/dev/null && brew install mythril 2>/dev/null; then
            log_ok "mythril (via brew)"
        else
            log_fail "mythril — try: pip3 install mythril (needs z3-solver, may need: brew install z3)"
        fi
    fi

    # === Surya — Code Visualization ===
    TOTAL=$((TOTAL + 1))
    if command -v surya &>/dev/null; then
        log_exists "surya"
    else
        log_install "surya"
        if command -v npm &>/dev/null && npm install -g surya 2>/dev/null; then
            log_ok "surya"
        else
            log_fail "surya — run: npm install -g surya"
        fi
    fi

    # === Solidity Metrics ===
    TOTAL=$((TOTAL + 1))
    if command -v solidity-code-metrics &>/dev/null; then
        log_exists "solidity-code-metrics"
    else
        log_install "solidity-code-metrics"
        if command -v npm &>/dev/null && npm install -g solidity-code-metrics 2>/dev/null; then
            log_ok "solidity-code-metrics"
        else
            log_fail "solidity-code-metrics"
        fi
    fi

    # === Aderyn — Rust-based Solidity Analyzer ===
    TOTAL=$((TOTAL + 1))
    if command -v aderyn &>/dev/null; then
        log_exists "aderyn"
    else
        log_install "aderyn"
        if command -v cargo &>/dev/null && cargo install aderyn 2>/dev/null; then
            log_ok "aderyn"
        else
            log_fail "aderyn — run: cargo install aderyn"
        fi
    fi

    # === 4naly3er — C4 Report Generator ===
    try_git_install 4naly3er "https://github.com/Picodes/4naly3er.git" "npm install 2>/dev/null || true"

    # ── Rust & WASM / Soroban (LayerZero, Stellar) ───────────────────────

    # === Stellar CLI ===
    TOTAL=$((TOTAL + 1))
    if command -v stellar &>/dev/null || command -v soroban &>/dev/null; then
        log_exists "stellar-cli"
    else
        log_install "stellar-cli"
        if command -v cargo &>/dev/null && cargo install --locked stellar-cli 2>/dev/null; then
            log_ok "stellar-cli"
        else
            log_fail "stellar-cli — run: cargo install --locked stellar-cli"
        fi
    fi

    # === cargo-fuzz ===
    TOTAL=$((TOTAL + 1))
    if cargo fuzz --version &>/dev/null 2>&1; then
        log_exists "cargo-fuzz"
    else
        log_install "cargo-fuzz"
        if command -v cargo &>/dev/null && cargo install cargo-fuzz 2>/dev/null; then
            log_ok "cargo-fuzz"
        else
            log_fail "cargo-fuzz"
        fi
    fi

    # === cargo-audit ===
    TOTAL=$((TOTAL + 1))
    if command -v cargo-audit &>/dev/null; then
        log_exists "cargo-audit"
    else
        log_install "cargo-audit"
        if command -v cargo &>/dev/null && cargo install cargo-audit 2>/dev/null; then
            log_ok "cargo-audit"
        else
            log_fail "cargo-audit"
        fi
    fi

    # === Miri — Rust UB Detector (requires nightly via rustup) ===
    TOTAL=$((TOTAL + 1))
    if rustup +nightly component list 2>/dev/null | grep -q "miri.*installed"; then
        log_exists "miri"
    else
        log_install "miri (nightly toolchain)"
        # Install rustup if not present (brew-installed Rust doesn't include it)
        if ! command -v rustup &>/dev/null; then
            echo -e "    ${YELLOW}rustup not found — installing...${NC}"
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>/dev/null
            export PATH="$HOME/.cargo/bin:$PATH"
        fi
        if command -v rustup &>/dev/null; then
            rustup toolchain install nightly 2>/dev/null && \
            rustup +nightly component add miri 2>/dev/null && \
            log_ok "miri" || log_fail "miri"
        else
            log_fail "miri — rustup installation failed"
        fi
    fi

    # === Clippy (bundled with Rust) ===
    TOTAL=$((TOTAL + 1))
    if command -v cargo-clippy &>/dev/null || cargo clippy --version &>/dev/null 2>&1; then
        log_exists "clippy"
    else
        log_install "clippy"
        rustup component add clippy 2>/dev/null && log_ok "clippy" || log_fail "clippy"
    fi

    # === WABT — WebAssembly Binary Toolkit ===
    try_brew_install wasm-decompile "wabt"

    # === wasm-tools ===
    TOTAL=$((TOTAL + 1))
    if command -v wasm-tools &>/dev/null; then
        log_exists "wasm-tools"
    else
        log_install "wasm-tools"
        if command -v cargo &>/dev/null && cargo install wasm-tools 2>/dev/null; then
            log_ok "wasm-tools"
        else
            log_fail "wasm-tools"
        fi
    fi

    # === Rust WASM target for Soroban ===
    TOTAL=$((TOTAL + 1))
    if rustup target list 2>/dev/null | grep -q "wasm32.*installed"; then
        log_exists "wasm32 target"
    else
        log_install "wasm32 target (for Soroban)"
        if command -v rustup &>/dev/null; then
            rustup target add wasm32-unknown-unknown 2>/dev/null && log_ok "wasm32 target" || log_fail "wasm32 target"
        else
            log_skip "wasm32 target (rustup not available — install rustup first)"
        fi
    fi

    # ── Workflow & Analysis ──────────────────────────────────────────────

    # === Tenderly CLI ===
    TOTAL=$((TOTAL + 1))
    if command -v tenderly &>/dev/null; then
        log_exists "tenderly"
    else
        log_install "tenderly"
        if command -v brew &>/dev/null; then
            brew tap tenderly/tenderly 2>/dev/null && \
            brew install tenderly 2>/dev/null && \
            log_ok "tenderly" || log_fail "tenderly"
        else
            log_fail "tenderly — run: brew tap tenderly/tenderly && brew install tenderly"
        fi
    fi

    # === Difftastic — CLI structural diff (NOT Meld — headless-safe) ===
    try_brew_install difft "difftastic"

    # === Pyrometer — Abstract Interpretation ===
    TOTAL=$((TOTAL + 1))
    if command -v pyrometer &>/dev/null; then
        log_exists "pyrometer"
    else
        log_install "pyrometer"
        if command -v cargo &>/dev/null && cargo install pyrometer 2>/dev/null; then
            log_ok "pyrometer"
        else
            # Pyrometer is niche and often fails to compile — try git clone fallback
            local pyro_dir="$TOOLS_DIR/pyrometer"
            if [ -d "$pyro_dir" ]; then
                log_ok "pyrometer (git exists)"
            elif git clone --quiet --depth 1 https://github.com/nascentxyz/pyrometer.git "$pyro_dir" 2>/dev/null; then
                (cd "$pyro_dir" && cargo build --release 2>/dev/null) || true
                log_ok "pyrometer (via git)"
            else
                log_fail "pyrometer — compilation failed (niche tool, optional)"
            fi
        fi
    fi

    # === Solidity Coverage ===
    TOTAL=$((TOTAL + 1))
    if npm list -g solidity-coverage &>/dev/null 2>&1; then
        log_exists "solidity-coverage"
    else
        log_install "solidity-coverage"
        if command -v npm &>/dev/null && npm install -g solidity-coverage 2>/dev/null; then
            log_ok "solidity-coverage"
        else
            log_fail "solidity-coverage"
        fi
    fi

    echo ""
    echo -e "  ${CYAN}Web3 Quick Start:${NC}"
    echo -e "    forge init my-audit && cd my-audit"
    echo -e "    slither . --json -                  # Static analysis"
    echo -e "    forge test --fork-url https://mainnet.base.org -vvvv  # Fork test"
    echo -e "    cast block-number --rpc-url https://mainnet.base.org  # Chain query"
}

# ============================================================================
# WORDLISTS
# ============================================================================

install_wordlists() {
    log_header "Wordlists → $WORDLISTS_DIR"
    mkdir -p "$WORDLISTS_DIR"

    try_git_install SecLists             "https://github.com/danielmiessler/SecLists.git"
    try_git_install PayloadsAllTheThings "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    try_git_install OneListForAll        "https://github.com/six2dez/OneListForAll.git"

    # Override TOOLS_DIR temporarily for wordlists (they go to WORDLISTS_DIR)
}

# ============================================================================
# ESSENTIALS (Quick Start — 10 most important tools)
# ============================================================================

install_essentials() {
    log_header "Essential Tools (Quick Start)"

    try_go_install subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    try_go_install httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    try_go_install nuclei     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    try_go_install katana     "github.com/projectdiscovery/katana/cmd/katana@latest"
    try_go_install ffuf       "github.com/ffuf/ffuf/v2@latest"
    try_go_install dalfox     "github.com/hahwul/dalfox/v2@latest"
    try_go_install gau        "github.com/lc/gau/v2/cmd/gau@latest"
    try_go_install naabu      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    try_pip_install sqlmap     "sqlmap"
    try_brew_install nmap

    echo -e "\n${YELLOW}Updating Nuclei templates...${NC}"
    nuclei -update-templates 2>/dev/null || true
}

# ============================================================================
# CHECK — Audit all tools without installing
# ============================================================================

check_tools() {
    log_header "Tool Audit — Checking All 150 Plugins"

    local found=0
    local missing=0
    local missing_list=""

    cd "$(dirname "$0")/../plugins/core" 2>/dev/null || cd "$(dirname "$0")/.." 2>/dev/null || true

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    PLUGIN_DIR="$SCRIPT_DIR/plugins/core"

    if [ ! -d "$PLUGIN_DIR" ]; then
        echo -e "  ${RED}Plugin directory not found at $PLUGIN_DIR${NC}"
        return 1
    fi

    for yaml_file in $(find "$PLUGIN_DIR" -name "*.yaml" | sort); do
        name=$(grep '^name:' "$yaml_file" | head -1 | sed 's/^name: *//')
        category=$(basename "$(dirname "$yaml_file")")
        if command -v "$name" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} ${category}/${name} → $(which "$name")"
            found=$((found + 1))
        elif [ -d "$TOOLS_DIR/$name" ]; then
            echo -e "  ${GREEN}✅${NC} ${category}/${name} → $TOOLS_DIR/$name"
            found=$((found + 1))
        else
            echo -e "  ${RED}❌${NC} ${category}/${name}"
            missing=$((missing + 1))
            missing_list="$missing_list $name"
        fi
    done

    echo -e "\n${BOLD}══════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Installed:${NC} $found"
    echo -e "  ${RED}Missing:${NC}   $missing"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"

    if [ $missing -gt 0 ]; then
        echo -e "\n${YELLOW}To install everything:${NC}"
        echo -e "  bash scripts/install_tools.sh --all"
    fi
}

# ============================================================================
# SETUP PATH
# ============================================================================

setup_path() {
    log_header "PATH Setup"

    PATHS_TO_ADD=(
        "$HOME/go/bin"
        "$HOME/.local/bin"
    )

    SHELL_RC=""
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    fi

    for p in "${PATHS_TO_ADD[@]}"; do
        if [[ ":$PATH:" != *":$p:"* ]]; then
            export PATH="$PATH:$p"
            if [ -n "$SHELL_RC" ]; then
                if ! grep -q "$p" "$SHELL_RC" 2>/dev/null; then
                    echo "export PATH=\"\$PATH:$p\"" >> "$SHELL_RC"
                    echo -e "  ${GREEN}Added${NC} $p → $SHELL_RC"
                fi
            fi
        fi
    done

    echo -e "  ${CYAN}PATH is configured.${NC}"
}

# ============================================================================
# SUMMARY
# ============================================================================

print_summary() {
    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Installation Summary${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Installed/Exists:${NC} $INSTALLED / $TOTAL"
    echo -e "  ${RED}Failed:${NC}          $FAILED / $TOTAL"
    echo -e "  ${YELLOW}Skipped:${NC}         $SKIPPED / $TOTAL"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"

    if [ $FAILED -gt 0 ]; then
        echo -e "\n${YELLOW}Some tools failed. Re-run the script to retry.${NC}"
    fi

    echo -e "\n${CYAN}Make sure these are in your PATH:${NC}"
    echo -e "  export PATH=\$PATH:\$HOME/go/bin:\$HOME/.local/bin"
    echo ""
}

# ============================================================================
# MAIN
# ============================================================================

usage() {
    echo -e "${BOLD}hack-ai-v2 Tool Installer${NC}"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --all          Install ALL 183 tools (Go + Python + System + Git + Rust + NPM + Ruby + OPSEC + Web3 + Wordlists)"
    echo "  --essentials   Quick start: 10 essential tools (subfinder, httpx, nuclei, ffuf, etc.)"
    echo "  --go           Install Go tools only (52 tools)"
    echo "  --python       Install Python tools only (32 tools)"
    echo "  --system       Install system tools only — brew/apt (20 tools)"
    echo "  --git          Install git-based tools only (22 tools)"
    echo "  --rust         Install Rust tools only (3 tools)"
    echo "  --npm          Install NPM tools only (2 tools)"
    echo "  --web3         Install Web3/smart contract auditing tools (25 tools: Foundry, Slither, Echidna, etc.)"
    echo "  --opsec        Install OPSEC/anonymization tools (ProtonVPN, proxychains, SpoofMAC, macchanger)"
    echo "  --wordlists    Install wordlists only (SecLists, PayloadsAllTheThings, etc.)"
    echo "  --check        Audit — check which of 183 tools are installed"
    echo "  --help         Show this help message"
    echo ""
}

main() {
    local mode="${1:---help}"

    echo -e "${BOLD}${BLUE}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║       hack-ai-v2 Tool Installer       ║"
    echo "  ║    183 Security + Web3 Audit Tools    ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  OS: $OS | Go: $(go version 2>/dev/null | awk '{print $3}' || echo 'not found')"
    echo ""

    case "$mode" in
        --all)
            setup_path
            install_go_tools
            install_python_tools
            install_system_tools
            install_git_tools
            install_rust_tools
            install_npm_tools
            install_ruby_tools
            install_binary_tools
            install_opsec_tools
            install_web3_tools
            install_wordlists
            print_summary
            ;;
        --web3)
            install_web3_tools
            print_summary
            ;;
        --opsec)
            install_opsec_tools
            print_summary
            ;;
        --essentials)
            setup_path
            install_essentials
            print_summary
            ;;
        --go)
            setup_path
            install_go_tools
            print_summary
            ;;
        --python)
            install_python_tools
            print_summary
            ;;
        --system)
            install_system_tools
            print_summary
            ;;
        --git)
            install_git_tools
            print_summary
            ;;
        --rust)
            install_rust_tools
            print_summary
            ;;
        --npm)
            install_npm_tools
            print_summary
            ;;
        --wordlists)
            install_wordlists
            print_summary
            ;;
        --check)
            check_tools
            ;;
        --help|*)
            usage
            ;;
    esac
}

main "$@"

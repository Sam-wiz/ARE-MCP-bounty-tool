#!/bin/bash
# ============================================================================
# hack-ai-v2 — OPSEC Setup & Anonymization
# Quick setup for IP masking, MAC spoofing, and proxy chaining
# Usage: bash scripts/setup_opsec.sh [--status|--connect|--disconnect|--spoof-mac|--full]
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

# ============================================================================
# Helpers
# ============================================================================

banner() {
    echo -e "${BOLD}${BLUE}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║     hack-ai-v2 OPSEC Setup            ║"
    echo "  ║  IP Masking • MAC Spoofing • Proxies  ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✅${NC} $1 ${DIM}$(which "$1")${NC}"
        return 0
    else
        echo -e "  ${RED}❌${NC} $1 ${DIM}— not installed${NC}"
        return 1
    fi
}

get_public_ip() {
    curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "unavailable"
}

get_ip_info() {
    curl -s --max-time 10 "https://ipinfo.io/$1/json" 2>/dev/null || echo "{}"
}

get_mac_address() {
    local iface="${1:-en0}"
    ifconfig "$iface" 2>/dev/null | grep ether | awk '{print $2}' || echo "unknown"
}

# ============================================================================
# Status — Show current anonymization state
# ============================================================================

show_status() {
    echo -e "\n${BOLD}${CYAN}  ── Current OPSEC Status ──${NC}\n"

    # Public IP
    local ip
    ip=$(get_public_ip)
    local ip_info
    ip_info=$(get_ip_info "$ip")
    local country city org
    country=$(echo "$ip_info" | grep '"country"' | head -1 | sed 's/.*: *"\(.*\)".*/\1/' 2>/dev/null || echo "?")
    city=$(echo "$ip_info" | grep '"city"' | head -1 | sed 's/.*: *"\(.*\)".*/\1/' 2>/dev/null || echo "?")
    org=$(echo "$ip_info" | grep '"org"' | head -1 | sed 's/.*: *"\(.*\)".*/\1/' 2>/dev/null || echo "?")

    echo -e "  ${BOLD}Public IP:${NC}  $ip"
    echo -e "  ${BOLD}Location:${NC}   $city, $country"
    echo -e "  ${BOLD}ISP/Org:${NC}    $org"
    echo ""

    # MAC Address
    local iface="en0"
    if [ "$(uname -s)" == "Linux" ]; then iface="eth0"; fi
    local mac
    mac=$(get_mac_address "$iface")
    echo -e "  ${BOLD}MAC ($iface):${NC} $mac"
    echo ""

    # VPN Status
    echo -e "  ${BOLD}── VPN ──${NC}"
    if command -v protonvpn-cli &>/dev/null; then
        local vpn_status
        vpn_status=$(protonvpn-cli status 2>&1 || echo "Disconnected")
        if echo "$vpn_status" | grep -qi "connected"; then
            echo -e "  ${GREEN}●${NC} ProtonVPN: Connected"
            echo "$vpn_status" | grep -iE "server|ip|country|city" | sed 's/^/    /'
        else
            echo -e "  ${RED}●${NC} ProtonVPN: Disconnected"
        fi
    else
        echo -e "  ${DIM}  protonvpn-cli not installed${NC}"
    fi
    echo ""

    # Tor Status
    echo -e "  ${BOLD}── Tor ──${NC}"
    if command -v tor &>/dev/null; then
        if curl -s --socks5-hostname 127.0.0.1:9050 --max-time 5 https://check.torproject.org/api/ip 2>/dev/null | grep -q "true"; then
            local tor_ip
            tor_ip=$(curl -s --socks5-hostname 127.0.0.1:9050 --max-time 5 https://api.ipify.org 2>/dev/null || echo "?")
            echo -e "  ${GREEN}●${NC} Tor: Active (exit IP: $tor_ip)"
        else
            echo -e "  ${RED}●${NC} Tor: Not running"
        fi
    else
        echo -e "  ${DIM}  tor not installed${NC}"
    fi
    echo ""

    # proxychains
    echo -e "  ${BOLD}── Proxychains ──${NC}"
    if command -v proxychains4 &>/dev/null; then
        local pc_conf="/usr/local/etc/proxychains.conf"
        if [ -f "$pc_conf" ]; then
            echo -e "  ${GREEN}●${NC} proxychains4: Configured ($pc_conf)"
        elif [ -f "/etc/proxychains4.conf" ]; then
            echo -e "  ${GREEN}●${NC} proxychains4: Configured (/etc/proxychains4.conf)"
        else
            echo -e "  ${YELLOW}●${NC} proxychains4: Installed but no config found"
        fi
    elif command -v proxychains &>/dev/null; then
        echo -e "  ${GREEN}●${NC} proxychains: Available"
    else
        echo -e "  ${DIM}  proxychains not installed${NC}"
    fi
    echo ""
}

# ============================================================================
# Connect VPN — ProtonVPN with country selection
# ============================================================================

connect_vpn() {
    local country="${1:-}"

    if ! command -v protonvpn-cli &>/dev/null; then
        echo -e "${RED}ProtonVPN CLI not installed. Run: bash scripts/install_tools.sh --opsec${NC}"
        exit 1
    fi

    # Check if already connected
    if protonvpn-cli status 2>&1 | grep -qi "connected"; then
        echo -e "${YELLOW}Already connected to ProtonVPN. Disconnect first? (y/n)${NC}"
        read -r answer
        if [ "$answer" = "y" ]; then
            protonvpn-cli disconnect
        else
            exit 0
        fi
    fi

    if [ -z "$country" ]; then
        echo -e "${BOLD}Available countries (free tier includes US, NL, JP):${NC}"
        echo ""
        echo "  Common codes:"
        echo "    US — United States    NL — Netherlands"
        echo "    JP — Japan            CH — Switzerland"
        echo "    DE — Germany          GB — United Kingdom"
        echo "    FR — France           CA — Canada"
        echo "    AU — Australia        SG — Singapore"
        echo "    IN — India            BR — Brazil"
        echo ""
        echo -e "${CYAN}Enter country code (e.g. US, NL, JP):${NC}"
        read -r country
    fi

    country=$(echo "$country" | tr '[:lower:]' '[:upper:]')
    echo -e "${CYAN}Connecting to ProtonVPN ($country)...${NC}"

    if protonvpn-cli connect --cc "$country"; then
        echo -e "\n${GREEN}✅ Connected to ProtonVPN ($country)${NC}"
        echo -e "  New IP: $(get_public_ip)"
    else
        echo -e "\n${RED}❌ Failed to connect. Make sure you've logged in:${NC}"
        echo "  protonvpn-cli login <username>"
    fi
}

# ============================================================================
# Disconnect VPN
# ============================================================================

disconnect_vpn() {
    if ! command -v protonvpn-cli &>/dev/null; then
        echo -e "${RED}ProtonVPN CLI not installed.${NC}"
        exit 1
    fi

    echo -e "${CYAN}Disconnecting from ProtonVPN...${NC}"
    if protonvpn-cli disconnect 2>/dev/null; then
        echo -e "${GREEN}✅ Disconnected${NC}"
        echo -e "  Current IP: $(get_public_ip)"
    else
        echo -e "${YELLOW}Not connected or already disconnected.${NC}"
    fi
}

# ============================================================================
# Spoof MAC Address
# ============================================================================

spoof_mac() {
    local iface="${1:-}"

    # Auto-detect interface
    if [ -z "$iface" ]; then
        if [ "$(uname -s)" == "Darwin" ]; then
            iface="en0"
        else
            iface="eth0"
        fi
    fi

    local current_mac
    current_mac=$(get_mac_address "$iface")
    echo -e "  ${BOLD}Current MAC ($iface):${NC} $current_mac"

    if command -v spoof-mac &>/dev/null; then
        echo -e "${CYAN}Randomizing MAC via SpoofMAC...${NC}"
        sudo spoof-mac randomize "$iface"
        local new_mac
        new_mac=$(get_mac_address "$iface")
        echo -e "  ${GREEN}✅ New MAC ($iface):${NC} $new_mac"
    elif command -v macchanger &>/dev/null; then
        echo -e "${CYAN}Randomizing MAC via macchanger...${NC}"
        sudo ip link set "$iface" down 2>/dev/null
        sudo macchanger -r "$iface"
        sudo ip link set "$iface" up 2>/dev/null
        local new_mac
        new_mac=$(get_mac_address "$iface")
        echo -e "  ${GREEN}✅ New MAC ($iface):${NC} $new_mac"
    else
        echo -e "${RED}No MAC spoofing tool found. Install with: bash scripts/install_tools.sh --opsec${NC}"
        exit 1
    fi
}

# ============================================================================
# Restore MAC Address
# ============================================================================

restore_mac() {
    local iface="${1:-}"
    if [ -z "$iface" ]; then
        if [ "$(uname -s)" == "Darwin" ]; then iface="en0"; else iface="eth0"; fi
    fi

    if command -v spoof-mac &>/dev/null; then
        echo -e "${CYAN}Restoring original MAC...${NC}"
        sudo spoof-mac reset "$iface"
        echo -e "  ${GREEN}✅ MAC restored ($iface):${NC} $(get_mac_address "$iface")"
    elif command -v macchanger &>/dev/null; then
        sudo ip link set "$iface" down 2>/dev/null
        sudo macchanger -p "$iface"
        sudo ip link set "$iface" up 2>/dev/null
        echo -e "  ${GREEN}✅ MAC restored ($iface):${NC} $(get_mac_address "$iface")"
    else
        echo -e "${RED}No MAC spoofing tool found.${NC}"
    fi
}

# ============================================================================
# Start Tor
# ============================================================================

start_tor() {
    if ! command -v tor &>/dev/null; then
        echo -e "${RED}Tor not installed. Run: bash scripts/install_tools.sh --system${NC}"
        exit 1
    fi

    echo -e "${CYAN}Starting Tor...${NC}"
    if [ "$(uname -s)" == "Darwin" ]; then
        brew services start tor 2>/dev/null || tor &
    else
        sudo systemctl start tor 2>/dev/null || tor &
    fi

    # Wait for Tor to be ready
    echo -ne "  Waiting for Tor"
    for i in $(seq 1 15); do
        if curl -s --socks5-hostname 127.0.0.1:9050 --max-time 3 https://check.torproject.org/api/ip 2>/dev/null | grep -q "true"; then
            local tor_ip
            tor_ip=$(curl -s --socks5-hostname 127.0.0.1:9050 --max-time 5 https://api.ipify.org 2>/dev/null || echo "?")
            echo -e "\n  ${GREEN}✅ Tor is running (exit IP: $tor_ip)${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    echo -e "\n  ${RED}❌ Tor failed to start within 30 seconds${NC}"
    return 1
}

# ============================================================================
# Full OPSEC Setup — everything at once
# ============================================================================

full_setup() {
    banner

    echo -e "${BOLD}${CYAN}  ── Tool Check ──${NC}\n"
    check_tool protonvpn-cli || true
    check_tool proxychains4 || check_tool proxychains || true
    check_tool tor || true
    check_tool spoof-mac || check_tool macchanger || true
    echo ""

    local country="${1:-}"

    # Step 1: Spoof MAC
    echo -e "${BOLD}${CYAN}  ── Step 1: MAC Spoofing ──${NC}\n"
    spoof_mac
    echo ""

    # Step 2: Start Tor
    echo -e "${BOLD}${CYAN}  ── Step 2: Tor ──${NC}\n"
    start_tor || true
    echo ""

    # Step 3: Connect VPN
    echo -e "${BOLD}${CYAN}  ── Step 3: VPN ──${NC}\n"
    connect_vpn "$country"
    echo ""

    # Step 4: Show final status
    echo -e "${BOLD}${CYAN}  ── Final Status ──${NC}"
    show_status
}

# ============================================================================
# Full Teardown — restore everything
# ============================================================================

teardown() {
    banner
    echo -e "${BOLD}${RED}  ── Tearing down OPSEC ──${NC}\n"

    # Disconnect VPN
    if command -v protonvpn-cli &>/dev/null; then
        echo -e "${CYAN}Disconnecting ProtonVPN...${NC}"
        protonvpn-cli disconnect 2>/dev/null || true
        echo -e "  ${GREEN}✅${NC} VPN disconnected"
    fi

    # Stop Tor
    if command -v tor &>/dev/null; then
        echo -e "${CYAN}Stopping Tor...${NC}"
        if [ "$(uname -s)" == "Darwin" ]; then
            brew services stop tor 2>/dev/null || pkill tor 2>/dev/null || true
        else
            sudo systemctl stop tor 2>/dev/null || pkill tor 2>/dev/null || true
        fi
        echo -e "  ${GREEN}✅${NC} Tor stopped"
    fi

    # Restore MAC
    echo -e "${CYAN}Restoring MAC address...${NC}"
    restore_mac
    echo ""

    echo -e "  Current IP: $(get_public_ip)"
    echo -e "\n${GREEN}✅ OPSEC teardown complete${NC}"
}

# ============================================================================
# Main
# ============================================================================

usage() {
    echo -e "${BOLD}hack-ai-v2 OPSEC Setup${NC}"
    echo ""
    echo "Usage: $0 [OPTION] [ARGS]"
    echo ""
    echo "Options:"
    echo "  --status              Show current anonymization status"
    echo "  --connect [COUNTRY]   Connect ProtonVPN (e.g. --connect US)"
    echo "  --disconnect          Disconnect ProtonVPN"
    echo "  --spoof-mac [IFACE]   Randomize MAC address"
    echo "  --restore-mac [IFACE] Restore original MAC address"
    echo "  --start-tor           Start Tor service"
    echo "  --full [COUNTRY]      Full setup: MAC spoof + Tor + VPN"
    echo "  --teardown            Teardown: disconnect VPN + stop Tor + restore MAC"
    echo "  --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --status                   # Check current state"
    echo "  $0 --connect US               # Connect VPN to US"
    echo "  $0 --connect DE               # Connect VPN to Germany"
    echo "  $0 --full JP                   # Full setup with Japan IP"
    echo "  $0 --spoof-mac en0             # Randomize MAC on en0"
    echo "  $0 --teardown                  # Restore everything"
    echo ""
}

main() {
    local mode="${1:---help}"

    case "$mode" in
        --status)
            banner
            show_status
            ;;
        --connect)
            banner
            connect_vpn "${2:-}"
            ;;
        --disconnect)
            banner
            disconnect_vpn
            ;;
        --spoof-mac)
            banner
            spoof_mac "${2:-}"
            ;;
        --restore-mac)
            banner
            restore_mac "${2:-}"
            ;;
        --start-tor)
            banner
            start_tor
            ;;
        --full)
            full_setup "${2:-}"
            ;;
        --teardown)
            teardown
            ;;
        --help|*)
            usage
            ;;
    esac
}

main "$@"

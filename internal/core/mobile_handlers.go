package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// MOBILE TESTING HANDLERS
// ============================================================================

func (e *Engine) handleTestMobile(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	mode := "static"
	if m, ok := args["mode"].(string); ok {
		mode = m
	}

	apkPath, _ := args["apk_path"].(string)

	var results strings.Builder
	results.WriteString(fmt.Sprintf("📱 Mobile testing (mode: %s)\n\n", mode))

	if mode == "static" || mode == "full" {
		if apkPath == "" {
			return errorResult("apk_path is required for static analysis"), nil
		}

		// Decompile with apktool
		results.WriteString("=== APK Decompilation ===\n")
		decResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("apktool d -f %s -o /tmp/apk_decoded 2>&1 | tail -5", ShellEscape(apkPath)),
			"apktool", 120)
		results.WriteString(decResult.Content[0].Text)

		// Search for secrets
		results.WriteString("\n\n=== Secret Scanning ===\n")
		secretResult, _ := e.ExecuteRawCommand(ctx,
			`grep -rn --include="*.xml" --include="*.json" --include="*.properties" -iE "(api[_-]?key|secret|password|token|firebase|aws)" /tmp/apk_decoded/ 2>/dev/null | head -30`,
			"secret-scan", 60)
		results.WriteString(secretResult.Content[0].Text)

		// Decompile with jadx for Java source
		results.WriteString("\n\n=== Java Decompilation ===\n")
		jadxResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("jadx -d /tmp/jadx_output %s --show-bad-code 2>&1 | tail -5", ShellEscape(apkPath)),
			"jadx", 180)
		results.WriteString(jadxResult.Content[0].Text)

		// Search decompiled Java for hardcoded secrets
		results.WriteString("\n\n=== Java Source Secrets ===\n")
		javaSecrets, _ := e.ExecuteRawCommand(ctx,
			`grep -rn --include="*.java" -iE "(api[_-]?key|secret|password|token|firebase|aws|private_key)" /tmp/jadx_output/ 2>/dev/null | head -30`,
			"java-secrets", 60)
		results.WriteString(javaSecrets.Content[0].Text)
	}

	if mode == "dynamic" || mode == "full" {
		results.WriteString("\n=== Dynamic Analysis ===\n")
		// Check for ADB connection
		adbResult, _ := e.ExecuteRawCommand(ctx, "adb devices 2>/dev/null", "adb", 10)
		results.WriteString(adbResult.Content[0].Text)
	}

	return successResult(results.String()), nil
}

// handleDownloadApp downloads mobile app binaries using apkeep (Android) or ipatool (iOS)
func (e *Engine) handleDownloadApp(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	packageID, _ := args["package_id"].(string)
	if packageID == "" {
		return errorResult("package_id is required (e.g., com.instagram.android)"), nil
	}

	platform := "android"
	if p, ok := args["platform"].(string); ok && p != "" {
		platform = p
	}

	source := "apkpure"
	if s, ok := args["source"].(string); ok && s != "" {
		source = s
	}

	outputDir := "/tmp/app_downloads"
	if o, ok := args["output_dir"].(string); ok && o != "" {
		outputDir = o
	}

	var results strings.Builder
	results.WriteString(fmt.Sprintf("📦 App Download (platform: %s, source: %s)\n\n", platform, source))

	// Ensure output directory exists
	e.ExecuteRawCommand(ctx, fmt.Sprintf("mkdir -p %s", ShellEscape(outputDir)), "mkdir", 5)

	switch platform {
	case "android":
		var cmd string
		switch source {
		case "google-play":
			email, _ := args["email"].(string)
			token, _ := args["token"].(string)
			if email == "" || token == "" {
				return errorResult("google-play source requires 'email' and 'token' parameters. Use 'apkpure' source for no-auth downloads."), nil
			}
			cmd = fmt.Sprintf("apkeep -a %s -d google-play -e %s -t %s -o %s 2>&1",
				ShellEscape(packageID), ShellEscape(email), ShellEscape(token), ShellEscape(outputDir))
			results.WriteString("⚠️  Google Play source — use a burner account (ToS risk)\n\n")
		case "f-droid":
			cmd = fmt.Sprintf("apkeep -a %s -d f-droid -o %s 2>&1",
				ShellEscape(packageID), ShellEscape(outputDir))
			results.WriteString("🔓 F-Droid source — no auth needed, FOSS apps only\n\n")
		default: // apkpure (default, no auth)
			cmd = fmt.Sprintf("apkeep -a %s -o %s 2>&1",
				ShellEscape(packageID), ShellEscape(outputDir))
			results.WriteString("🔓 APKPure source — no auth needed\n\n")
		}

		results.WriteString("=== Downloading APK ===\n")
		dlResult, _ := e.ExecuteRawCommand(ctx, cmd, "apkeep", 300)
		results.WriteString(dlResult.Content[0].Text)

		// List downloaded files
		results.WriteString("\n\n=== Downloaded Files ===\n")
		lsResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("ls -la %s/%s* 2>/dev/null || echo 'No files found — check package ID'", ShellEscape(outputDir), ShellEscape(packageID)),
			"ls", 5)
		results.WriteString(lsResult.Content[0].Text)

	case "ios":
		results.WriteString("🍎 iOS — requires Apple ID authentication\n\n")
		results.WriteString("=== Downloading IPA ===\n")

		cmd := fmt.Sprintf("ipatool download -b %s -o %s 2>&1",
			ShellEscape(packageID), ShellEscape(outputDir))
		dlResult, _ := e.ExecuteRawCommand(ctx, cmd, "ipatool", 300)
		results.WriteString(dlResult.Content[0].Text)

		// List downloaded files
		results.WriteString("\n\n=== Downloaded Files ===\n")
		lsResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("ls -la %s/*.ipa 2>/dev/null || echo 'No IPA found — ensure ipatool auth: ipatool auth login'", ShellEscape(outputDir)),
			"ls", 5)
		results.WriteString(lsResult.Content[0].Text)

	default:
		return errorResult(fmt.Sprintf("Unknown platform: %s (use 'android' or 'ios')", platform)), nil
	}

	results.WriteString(fmt.Sprintf("\n\n💡 Next: use test_mobile with the downloaded file for static analysis"))

	return successResult(results.String()), nil
}

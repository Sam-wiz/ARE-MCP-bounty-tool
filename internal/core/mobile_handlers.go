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

// handleDownloadApp downloads an APK from Google Play/APKPure or an IPA from the App Store.
// APKPure source requires no authentication. Google Play and App Store require credentials.
func (e *Engine) handleDownloadApp(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	platform, _ := args["platform"].(string)
	if platform == "" {
		platform = "android"
	}

	packageID, _ := args["package_id"].(string)
	if packageID == "" {
		return errorResult("package_id is required (Android: com.example.app, iOS: com.example.app bundle ID)"), nil
	}

	outputDir := "/tmp/apks"
	if d, ok := args["output_dir"].(string); ok && d != "" {
		outputDir = d
	}

	var results strings.Builder

	switch platform {
	case "android":
		source := "apkpure"
		if s, ok := args["source"].(string); ok && s != "" {
			source = s
		}

		results.WriteString(fmt.Sprintf("📦 Downloading APK: %s (source: %s)\n\n", packageID, source))

		mkdirResult, _ := e.ExecuteRawCommand(ctx, fmt.Sprintf("mkdir -p %s", ShellEscape(outputDir)), "mkdir", 5)
		_ = mkdirResult

		var cmd string
		if source == "google-play" {
			email, _ := args["email"].(string)
			password, _ := args["password"].(string)
			if email == "" || password == "" {
				return errorResult("email and password are required for google-play source"), nil
			}
			cmd = fmt.Sprintf("apkeep -a %s -d google-play --username %s --password %s %s 2>&1",
				ShellEscape(packageID), ShellEscape(email), ShellEscape(password), ShellEscape(outputDir))
		} else {
			// apkpure — no auth required
			cmd = fmt.Sprintf("apkeep -a %s -d apkpure %s 2>&1", ShellEscape(packageID), ShellEscape(outputDir))
		}

		dlResult, _ := e.ExecuteRawCommand(ctx, cmd, "apkeep", 120)
		results.WriteString(dlResult.Content[0].Text)

		// Show downloaded file
		lsResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("ls -lh %s/*.apk 2>/dev/null | tail -5", ShellEscape(outputDir)),
			"ls", 5)
		results.WriteString("\n\n=== Downloaded Files ===\n")
		results.WriteString(lsResult.Content[0].Text)

	case "ios":
		bundleID := packageID
		email, _ := args["email"].(string)
		password, _ := args["password"].(string)

		results.WriteString(fmt.Sprintf("📦 Downloading IPA: %s\n\n", bundleID))

		mkdirResult, _ := e.ExecuteRawCommand(ctx, fmt.Sprintf("mkdir -p %s", ShellEscape(outputDir)), "mkdir", 5)
		_ = mkdirResult

		// Auth first if credentials provided
		if email != "" && password != "" {
			authCmd := fmt.Sprintf("ipatool auth login --email %s --password %s 2>&1",
				ShellEscape(email), ShellEscape(password))
			authResult, _ := e.ExecuteRawCommand(ctx, authCmd, "ipatool-auth", 30)
			results.WriteString("=== Auth ===\n")
			results.WriteString(authResult.Content[0].Text)
			results.WriteString("\n\n")
		}

		dlCmd := fmt.Sprintf("ipatool download -b %s --output %s 2>&1", ShellEscape(bundleID), ShellEscape(outputDir))
		dlResult, _ := e.ExecuteRawCommand(ctx, dlCmd, "ipatool", 180)
		results.WriteString(dlResult.Content[0].Text)

		// Show downloaded file
		lsResult, _ := e.ExecuteRawCommand(ctx,
			fmt.Sprintf("ls -lh %s/*.ipa 2>/dev/null | tail -5", ShellEscape(outputDir)),
			"ls", 5)
		results.WriteString("\n\n=== Downloaded Files ===\n")
		results.WriteString(lsResult.Content[0].Text)

	default:
		return errorResult(fmt.Sprintf("Unknown platform: %s (use 'android' or 'ios')", platform)), nil
	}

	return successResult(results.String()), nil
}

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

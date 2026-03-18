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

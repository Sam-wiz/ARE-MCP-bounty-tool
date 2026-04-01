// Package core - executor.go implements the command execution engine.
// This is the "Puppeteer" — Go actually runs the tools, captures output, parses it.
package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/storage"
	"github.com/samrudh/hack-ai-v2/internal/types"
	"github.com/samrudh/hack-ai-v2/internal/workspace"
)

// ShellEscape escapes a string for safe use in shell commands.
// Wraps the value in single quotes and escapes any embedded single quotes.
func ShellEscape(s string) string {
	// Replace single quotes with '\'' (end quote, escaped quote, start quote)
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	return "'" + escaped + "'"
}

// buildCommand constructs the shell command from a plugin definition and arguments
func buildCommand(plugin *types.PluginDefinition, args map[string]interface{}) (string, error) {
	cmdTemplate := plugin.Execute.Command
	if cmdTemplate == "" {
		return "", fmt.Errorf("plugin %s has no execute command defined", plugin.Name)
	}

	// Replace placeholders with actual argument values (shell-escaped)
	result := cmdTemplate
	for paramName, paramDef := range plugin.Execute.Input {
		placeholder := "{" + paramName + "}"

		if val, ok := args[paramName]; ok {
			var strVal string
			switch v := val.(type) {
			case string:
				strVal = ShellEscape(v)
			case float64:
				strVal = fmt.Sprintf("%.0f", v)
			case bool:
				if v {
					strVal = "true"
				} else {
					strVal = "false"
				}
			case []interface{}:
				parts := make([]string, len(v))
				for i, item := range v {
					parts[i] = ShellEscape(fmt.Sprintf("%v", item))
				}
				strVal = strings.Join(parts, ",")
			default:
				strVal = ShellEscape(fmt.Sprintf("%v", v))
			}
			result = strings.ReplaceAll(result, placeholder, strVal)
		} else if paramDef.Default != "" {
			result = strings.ReplaceAll(result, placeholder, paramDef.Default)
		} else if paramDef.Required {
			return "", fmt.Errorf("required parameter %s not provided for %s", paramName, plugin.Name)
		} else {
			// Optional param not provided — remove the placeholder
			result = strings.ReplaceAll(result, placeholder, "")
		}
	}

	// Clean up double spaces from removed optional params
	for strings.Contains(result, "  ") {
		result = strings.ReplaceAll(result, "  ", " ")
	}
	result = strings.TrimSpace(result)

	return result, nil
}

// executeCommand runs a shell command and captures its output
func executeCommand(ctx context.Context, cmdStr string, timeoutSec int) (stdout string, stderr string, exitCode int, err error) {
	if timeoutSec <= 0 {
		timeoutSec = 300 // 5 minute default
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "/bin/sh", "-c", cmdStr)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	log.Printf("[EXECUTOR] Running: %s", cmdStr)
	startTime := time.Now()

	err = cmd.Run()
	elapsed := time.Since(startTime)

	exitCode = 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	log.Printf("[EXECUTOR] Completed in %v (exit: %d)", elapsed, exitCode)

	return stdoutBuf.String(), stderrBuf.String(), exitCode, err
}

// checkToolInstalled verifies a tool binary exists on the system.
// For git-cloned tools whose verify command requires a specific CWD,
// we fall back to checking if the tool's base binary is on PATH.
func checkToolInstalled(plugin *types.PluginDefinition) error {
	if plugin.Install.Verify == "" {
		return nil
	}

	// Try the verify command first
	cmd := exec.Command("/bin/sh", "-c", plugin.Install.Verify)
	if err := cmd.Run(); err != nil {
		// Verify failed — try to find the tool binary on PATH as fallback.
		// Extract the first word of the execute command as the binary name.
		binName := plugin.Execute.Command
		if idx := strings.IndexByte(binName, ' '); idx > 0 {
			binName = binName[:idx]
		}
		// Strip leading path components (e.g., "python3" from "python3 corsy.py")
		if _, lookErr := exec.LookPath(binName); lookErr != nil {
			return fmt.Errorf("tool %s not installed (verify: %s failed: %v). Install with: %s",
				plugin.Name, plugin.Install.Verify, err, plugin.Install.Command)
		}
		log.Printf("[EXECUTOR] %s: verify command failed but binary %q found on PATH, continuing", plugin.Name, binName)
	}
	return nil
}

// ExecutePluginFull is the complete plugin execution pipeline:
// check installed → build command → execute → parse → create findings → persist to MongoDB
func (e *Engine) ExecutePluginFull(ctx context.Context, plugin *types.PluginDefinition, args map[string]interface{}) (types.ToolResult, error) {
	// 1. Check if tool is installed
	if err := checkToolInstalled(plugin); err != nil {
		return errorResult(fmt.Sprintf("🔧 Tool not installed: %v", err)), nil
	}

	// 2. Build the command
	cmdStr, err := buildCommand(plugin, args)
	if err != nil {
		return errorResult(fmt.Sprintf("❌ Failed to build command: %v", err)), nil
	}

	// 3. Execute the command
	startedAt := time.Now()
	stdout, stderr, exitCode, execErr := executeCommand(ctx, cmdStr, plugin.Execute.Timeout)
	duration := time.Since(startedAt)

	// 4. Parse the output
	parseResult, parseErr := ParseToolOutput(plugin, stdout, e.getSessionID())

	// 5. Store findings in memory and MongoDB
	var findingIDs []string
	if parseResult != nil {
		for _, finding := range parseResult.Findings {
			e.mu.Lock()
			e.findings[finding.ID] = finding
			e.mu.Unlock()
			findingIDs = append(findingIDs, finding.ID)

			if e.config.MongoDB != nil {
				if saveErr := e.config.MongoDB.SaveFinding(ctx, finding); saveErr != nil {
					log.Printf("[EXECUTOR] Failed to save finding %s: %v", finding.ID, saveErr)
				}
			}
		}
	}

	// 6. Log the tool run to MongoDB (using storage.ToolRun type)
	if e.config.MongoDB != nil {
		success := execErr == nil
		errStr := ""
		if execErr != nil {
			errStr = execErr.Error()
		}
		toolRun := &storage.ToolRun{
			SessionID: e.getSessionID(),
			ToolName:  plugin.Name,
			Args:      cmdStr,
			Output:    truncateString(stdout, 50000),
			Duration:  duration,
			Success:   success,
			Error:     errStr,
		}
		if logErr := e.config.MongoDB.LogToolRun(ctx, toolRun); logErr != nil {
			log.Printf("[EXECUTOR] Failed to log tool run: %v", logErr)
		}
	}

	// 7. Build summary for the LLM
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ Executed: %s\n", plugin.Name))
	summary.WriteString(fmt.Sprintf("📋 Command: %s\n", cmdStr))
	summary.WriteString(fmt.Sprintf("⏱️  Duration: %v | Exit: %d\n", duration.Round(time.Millisecond), exitCode))

	if execErr != nil {
		summary.WriteString(fmt.Sprintf("⚠️  Error: %v\n", execErr))
	}
	if stderr != "" && len(stderr) < 500 {
		summary.WriteString(fmt.Sprintf("📝 Stderr: %s\n", strings.TrimSpace(stderr)))
	}

	if parseResult != nil && len(parseResult.Findings) > 0 {
		summary.WriteString(fmt.Sprintf("🔍 Findings: %d items parsed (%s format)\n", parseResult.ItemCount, parseResult.ParseType))
		summary.WriteString("📦 Saved to MongoDB: ✅\n\n")

		limit := 10
		if len(parseResult.Findings) < limit {
			limit = len(parseResult.Findings)
		}
		summary.WriteString("--- Top Results ---\n")
		for i := 0; i < limit; i++ {
			f := parseResult.Findings[i]
			line := f.Title
			if line == "" {
				line = f.URL
			}
			if line == "" {
				line = f.Target
			}
			if f.Severity != "" {
				line += fmt.Sprintf(" [%s]", f.Severity)
			}
			summary.WriteString(fmt.Sprintf("%d. %s\n", i+1, line))
		}
		if len(parseResult.Findings) > limit {
			summary.WriteString(fmt.Sprintf("... and %d more\n", len(parseResult.Findings)-limit))
		}
	} else {
		summary.WriteString("📝 No structured findings parsed from output.\n")
		raw := smartTruncate(stdout, 2000)
		if raw != "" {
			summary.WriteString("\n--- Raw Output ---\n")
			summary.WriteString(raw)
		}
	}

	if parseErr != nil {
		summary.WriteString(fmt.Sprintf("\n⚠️  Parse warning: %v\n", parseErr))
	}

	return successResult(summary.String()), nil
}

// ExecuteRawCommand runs an arbitrary command and logs it to MongoDB
func (e *Engine) ExecuteRawCommand(ctx context.Context, command string, toolName string, timeoutSec int) (types.ToolResult, error) {
	startedAt := time.Now()
	stdout, stderr, exitCode, execErr := executeCommand(ctx, command, timeoutSec)
	duration := time.Since(startedAt)

	// Log to MongoDB
	if e.config.MongoDB != nil {
		success := execErr == nil
		errStr := ""
		if execErr != nil {
			errStr = execErr.Error()
		}
		toolRun := &storage.ToolRun{
			SessionID: e.getSessionID(),
			ToolName:  toolName,
			Args:      command,
			Output:    truncateString(stdout, 50000),
			Duration:  duration,
			Success:   success,
			Error:     errStr,
		}
		e.config.MongoDB.LogToolRun(ctx, toolRun)
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ Executed: %s\n", toolName))
	summary.WriteString(fmt.Sprintf("📋 Command: %s\n", command))
	summary.WriteString(fmt.Sprintf("⏱️  Duration: %v | Exit: %d\n", duration.Round(time.Millisecond), exitCode))

	if execErr != nil {
		summary.WriteString(fmt.Sprintf("⚠️  Error: %v\n", execErr))
	}
	if stderr != "" && len(stderr) < 1000 {
		summary.WriteString(fmt.Sprintf("📝 Stderr: %s\n", strings.TrimSpace(stderr)))
	}

	raw := smartTruncate(stdout, 5000)
	if raw != "" {
		summary.WriteString("\n--- Output ---\n")
		summary.WriteString(raw)
	}

	return successResult(summary.String()), nil
}

// truncateString limits string length for storage (MongoDB)
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("\n... (truncated, total %d bytes)", len(s))
}

// smartTruncate keeps the head and tail of a long string, dropping the useless middle.
// This prevents token bloat for LLM responses while keeping the crucial start/end context.
func smartTruncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	half := maxLen / 2
	head := s[:half]
	tail := s[len(s)-half:]
	dropped := len(s) - maxLen

	return fmt.Sprintf("%s\n\n... [TRUNCATED %d BYTES - Check artifacts folder] ...\n\n%s", head, dropped, tail)
}

// ============================================================================
// SANDBOX EXECUTION — execute_hunting_script
// ============================================================================

// ExecuteHuntingScript runs a Python or Bash script inside a sandboxed environment.
func (e *Engine) ExecuteHuntingScript(
	ctx context.Context,
	code string,
	runtime string,
	scriptName string,
	secrets map[string]string,
	dependencies []string,
	ws *workspace.Workspace,
) (types.ToolResult, error) {

	// ── Step 0: Proxy Liveness Check ────────────────────────────────────
	proxyAddr := "127.0.0.1:8080"
	if e.config.Config != nil && e.config.Config.Sandbox.MitmproxyPort > 0 {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", e.config.Config.Sandbox.MitmproxyPort)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return errorResult(fmt.Sprintf(
			"⛔ Proxy offline at %s. Start mitmproxy:\n  mitmproxy -s scripts/scope_enforcer.py --listen-port %s\n\nError: %v",
			proxyAddr, proxyAddr[strings.LastIndex(proxyAddr, ":")+1:], err,
		)), nil
	}
	conn.Close()

	// ── Step 1: Resolve paths ───────────────────────────────────────────
	if scriptName == "" {
		scriptName = "script"
	}
	// Sanitize script name for filesystem safety
	safeName := sanitizeScriptName(scriptName)
	ts := time.Now().Unix()

	var ext string
	switch runtime {
	case "python":
		ext = "py"
	case "bash":
		ext = "sh"
	default:
		return errorResult(fmt.Sprintf("❌ Unsupported runtime: %s (must be 'python' or 'bash')", runtime)), nil
	}

	testsDir := ws.GetTestsPath()
	artifactsDir := ws.GetArtifactsPath()
	os.MkdirAll(testsDir, 0755)
	os.MkdirAll(artifactsDir, 0755)

	scriptFile := filepath.Join(testsDir, fmt.Sprintf("%s_%d.%s", safeName, ts, ext))
	logFile := filepath.Join(artifactsDir, fmt.Sprintf("%s_%d.log", safeName, ts))

	// ── Step 2: Install on-demand dependencies ──────────────────────────
	if len(dependencies) > 0 && runtime == "python" {
		log.Printf("[SANDBOX] Installing dependencies: %v", dependencies)
		wsMgr := workspace.NewManager("")
		if depErr := wsMgr.InstallDependencies(ws.Path, dependencies); depErr != nil {
			return errorResult(fmt.Sprintf("❌ Failed to install dependencies %v: %v", dependencies, depErr)), nil
		}
	}

	// ── Step 3: Save script to disk ─────────────────────────────────────
	if err := os.WriteFile(scriptFile, []byte(code), 0644); err != nil {
		return errorResult(fmt.Sprintf("❌ Failed to save script: %v", err)), nil
	}
	log.Printf("[SANDBOX] Script saved: %s", scriptFile)

	// ── Step 4: Build command ───────────────────────────────────────────
	var interpreter string
	switch runtime {
	case "python":
		interpreter = ws.GetVenvPython()
		// Verify venv exists
		if _, err := os.Stat(interpreter); os.IsNotExist(err) {
			return errorResult(fmt.Sprintf(
				"❌ Venv Python not found at %s. Run set_program to create workspace first.", interpreter,
			)), nil
		}
	case "bash":
		interpreter = "/bin/bash"
	}

	cmd := exec.CommandContext(ctx, interpreter, scriptFile)
	cmd.Dir = ws.Path

	// ── Step 6: Build sandboxed environment ─────────────────────────────
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)
	caCert := ""
	if e.config.Config != nil {
		caCert = e.config.Config.Sandbox.MitmproxyCACert
	}

	env := os.Environ() // inherit PATH and basic env
	env = append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
	)
	if caCert != "" {
		env = append(env,
			"REQUESTS_CA_BUNDLE="+caCert,
			"SSL_CERT_FILE="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
			"CURL_CA_BUNDLE="+caCert,
		)
	}
	// Inject secrets into env
	secretKeys := make([]string, 0, len(secrets))
	for k, v := range secrets {
		env = append(env, k+"="+v)
		secretKeys = append(secretKeys, k) // track key names only
	}
	cmd.Env = env

	// ── Step 7: Open log file and wire stdout/stderr ────────────────────
	logFd, err := os.Create(logFile)
	if err != nil {
		return errorResult(fmt.Sprintf("❌ Failed to create log file: %v", err)), nil
	}
	defer logFd.Close()

	// Write header to log
	fmt.Fprintf(logFd, "=== hack-ai-v2 Sandbox Execution ===\n")
	fmt.Fprintf(logFd, "Script:    %s\n", scriptFile)
	fmt.Fprintf(logFd, "Runtime:   %s\n", runtime)
	fmt.Fprintf(logFd, "Timestamp: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(logFd, "Proxy:     %s\n", proxyURL)
	if len(dependencies) > 0 {
		fmt.Fprintf(logFd, "Deps:      %v\n", dependencies)
	}
	fmt.Fprintf(logFd, "=====================================\n\n")

	var outputBuf bytes.Buffer
	multiOut := io.MultiWriter(logFd, &outputBuf)

	// ── Step 8: Execute with timeout ────────────────────────────────────
	timeout := 600 // default 10 min
	if e.config.Config != nil && e.config.Config.Sandbox.ScriptTimeout > 0 {
		timeout = e.config.Config.Sandbox.ScriptTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	cmd = exec.CommandContext(execCtx, interpreter, scriptFile)
	cmd.Dir = ws.Path
	cmd.Env = env
	cmd.Stdout = multiOut
	cmd.Stderr = multiOut

	log.Printf("[SANDBOX] Executing: %s %s", interpreter, scriptFile)
	startTime := time.Now()

	execErr := cmd.Run()
	duration := time.Since(startTime)

	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	// Write footer to log
	fmt.Fprintf(logFd, "\n\n=====================================\n")
	fmt.Fprintf(logFd, "Exit Code: %d\n", exitCode)
	fmt.Fprintf(logFd, "Duration:  %v\n", duration.Round(time.Millisecond))
	if execErr != nil {
		fmt.Fprintf(logFd, "Error:     %v\n", execErr)
	}
	fmt.Fprintf(logFd, "=====================================\n")

	log.Printf("[SANDBOX] Completed in %v (exit: %d)", duration, exitCode)

	// ── Step 9: Log to MongoDB ──────────────────────────────────────────
	if e.config.MongoDB != nil {
		success := execErr == nil
		errStr := ""
		if execErr != nil {
			errStr = execErr.Error()
		}
		scriptExec := &types.ScriptExecution{
			Program:      e.GetProgram(),
			SessionID:    e.getSessionID(),
			Timestamp:    startTime,
			Runtime:      runtime,
			ScriptName:   scriptName,
			ScriptPath:   scriptFile,
			ArtifactLog:  logFile,
			ExitCode:     exitCode,
			Duration:     duration,
			Success:      success,
			Error:        errStr,
			SecretsUsed:  secretKeys,
			Dependencies: dependencies,
		}
		if logErr := e.config.MongoDB.LogScriptExecution(ctx, scriptExec); logErr != nil {
			log.Printf("[SANDBOX] Failed to log execution to MongoDB: %v", logErr)
		}
	}

	// ── Step 10: Build LLM response ─────────────────────────────────────
	fullOutput := outputBuf.String()
	
	// FIX: Use smartTruncate instead of tailString to keep headers/status
	snippet := smartTruncate(fullOutput, 2000)

	var result strings.Builder
	result.WriteString(fmt.Sprintf("🔒 Sandboxed Execution Complete\n"))
	result.WriteString(fmt.Sprintf("📄 Script:   %s\n", scriptFile))
	result.WriteString(fmt.Sprintf("📋 Log:      %s\n", logFile))
	result.WriteString(fmt.Sprintf("⏱️  Duration: %v | Exit: %d\n", duration.Round(time.Millisecond), exitCode))
	result.WriteString(fmt.Sprintf("🌐 Proxy:    %s (scope enforced)\n", proxyURL))

	if execErr != nil {
		result.WriteString(fmt.Sprintf("⚠️  Error: %v\n", execErr))
	}
	if len(dependencies) > 0 {
		result.WriteString(fmt.Sprintf("📦 Deps installed: %v\n", dependencies))
	}

	result.WriteString("\n--- Output (Smart Truncated: First 1000 + Last 1000 chars) ---\n")
	result.WriteString(snippet)
	result.WriteString("\n\n💾 Full output preserved at: " + logFile)

	return successResult(result.String()), nil
}

// sanitizeScriptName makes a script name filesystem-safe
func sanitizeScriptName(name string) string {
	safe := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe += string(r)
		} else if r == ' ' {
			safe += "_"
		}
	}
	if safe == "" {
		safe = "script"
	}
	return safe
}
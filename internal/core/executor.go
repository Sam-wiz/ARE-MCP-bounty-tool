// Package core - executor.go implements the command execution engine.
// This is the "Puppeteer" — Go actually runs the tools, captures output, parses it.
package core

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/storage"
	"github.com/samrudh/hack-ai-v2/internal/types"
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
		raw := truncateString(stdout, 2000)
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

	raw := truncateString(stdout, 5000)
	if raw != "" {
		summary.WriteString("\n--- Output ---\n")
		summary.WriteString(raw)
	}

	return successResult(summary.String()), nil
}

// truncateString limits string length for output/storage
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("\n... (truncated, total %d bytes)", len(s))
}

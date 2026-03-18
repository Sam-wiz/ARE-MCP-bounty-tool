// Package reporting implements report generation
package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// Generator handles report generation
type Generator struct {
	outputDir string
}

// Report represents a vulnerability report
type Report struct {
	Title       string            `json:"title"`
	Target      string            `json:"target"`
	GeneratedAt time.Time         `json:"generated_at"`
	Summary     ReportSummary     `json:"summary"`
	Findings    []ReportFinding   `json:"findings"`
	ToolsUsed   []string          `json:"tools_used"`
	Methodology string            `json:"methodology"`
	Appendix    map[string]string `json:"appendix,omitempty"`
}

// ReportSummary provides overview statistics
type ReportSummary struct {
	TotalFindings     int            `json:"total_findings"`
	BySeverity        map[string]int `json:"by_severity"`
	ByState           map[string]int `json:"by_state"`
	ByVulnType        map[string]int `json:"by_vuln_type"`
	CriticalFindings  int            `json:"critical_findings"`
	VerifiedFindings  int            `json:"verified_findings"`
	ExploitedFindings int            `json:"exploited_findings"`
}

// ReportFinding represents a finding in the report
type ReportFinding struct {
	ID           string      `json:"id"`
	Title        string      `json:"title"`
	Severity     string      `json:"severity"`
	VulnType     string      `json:"vuln_type"`
	State        string      `json:"state"`
	Description  string      `json:"description"`
	Impact       string      `json:"impact"`
	Remediation  string      `json:"remediation"`
	Endpoint     string      `json:"endpoint"`
	PoC          *types.PoC  `json:"poc,omitempty"`
	Evidence     []string    `json:"evidence,omitempty"`
	OWASP        string      `json:"owasp,omitempty"`
	CWE          string      `json:"cwe,omitempty"`
	CVSSScore    float64     `json:"cvss_score,omitempty"`
	References   []string    `json:"references,omitempty"`
}

// NewGenerator creates a new report generator
func NewGenerator(outputDir string) *Generator {
	if outputDir == "" {
		outputDir = "/tmp/hack-ai-v2/reports"
	}
	os.MkdirAll(outputDir, 0755)
	return &Generator{outputDir: outputDir}
}

// Generate creates a report from findings
func (g *Generator) Generate(findings []*types.Finding, target string, toolsUsed []string) (*Report, error) {
	report := &Report{
		Title:       fmt.Sprintf("Security Assessment - %s", target),
		Target:      target,
		GeneratedAt: time.Now(),
		ToolsUsed:   toolsUsed,
		Summary:     g.generateSummary(findings),
		Findings:    g.convertFindings(findings),
		Methodology: g.generateMethodology(toolsUsed),
	}
	
	return report, nil
}

// SaveJSON saves report as JSON
func (g *Generator) SaveJSON(report *Report) (string, error) {
	filename := filepath.Join(g.outputDir, fmt.Sprintf("report_%d.json", time.Now().Unix()))
	
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", err
	}
	
	return filename, nil
}

// SaveMarkdown saves report as Markdown
func (g *Generator) SaveMarkdown(report *Report) (string, error) {
	filename := filepath.Join(g.outputDir, fmt.Sprintf("report_%d.md", time.Now().Unix()))
	
	md := g.generateMarkdown(report)
	
	if err := os.WriteFile(filename, []byte(md), 0644); err != nil {
		return "", err
	}
	
	return filename, nil
}

// generateSummary creates summary statistics
func (g *Generator) generateSummary(findings []*types.Finding) ReportSummary {
	summary := ReportSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByState:       make(map[string]int),
		ByVulnType:    make(map[string]int),
	}
	
	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByState[string(f.State)]++
		summary.ByVulnType[f.VulnType]++
		
		if f.Severity == "critical" {
			summary.CriticalFindings++
		}
		if f.State == types.FindingVerified || f.State == types.FindingExploited {
			summary.VerifiedFindings++
		}
		if f.State == types.FindingExploited {
			summary.ExploitedFindings++
		}
	}
	
	return summary
}

// convertFindings converts internal findings to report format
func (g *Generator) convertFindings(findings []*types.Finding) []ReportFinding {
	reportFindings := make([]ReportFinding, 0, len(findings))
	
	for _, f := range findings {
		rf := ReportFinding{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			VulnType:    f.VulnType,
			State:       string(f.State),
			Description: f.Description,
			Impact:      g.generateImpact(f),
			Remediation: g.generateRemediation(f),
			Endpoint:    f.Endpoint,
			PoC:         f.PoC,
			Evidence:    f.Evidence,
			OWASP:       f.OWASP,
			CWE:         f.CWE,
			CVSSScore:   f.CVSSScore,
			References:  g.getReferences(f),
		}
		reportFindings = append(reportFindings, rf)
	}
	
	return reportFindings
}

// generateMethodology creates methodology section
func (g *Generator) generateMethodology(tools []string) string {
	return fmt.Sprintf(`## Methodology

The security assessment followed a systematic approach:

1. **Reconnaissance**: Subdomain enumeration, technology fingerprinting
2. **Active Scanning**: Vulnerability scanning with multiple tools
3. **Manual Testing**: Targeted testing of identified vulnerabilities
4. **Verification**: Secondary verification of all findings
5. **PoC Development**: Proof of concept creation for verified vulnerabilities
6. **Evidence Collection**: Screenshot and traffic capture

### Tools Used
%s`, strings.Join(tools, "\n- "))
}

// generateImpact generates impact description
func (g *Generator) generateImpact(f *types.Finding) string {
	impacts := map[string]string{
		"sqli":      "SQL Injection can lead to unauthorized data access, data modification, and potentially complete database compromise.",
		"xss":       "Cross-Site Scripting can be used to steal user sessions, deface websites, or redirect users to malicious sites.",
		"ssrf":      "Server-Side Request Forgery can expose internal services, access cloud metadata, and potentially lead to remote code execution.",
		"rce":       "Remote Code Execution allows attackers to execute arbitrary commands on the server, leading to complete system compromise.",
		"idor":      "Insecure Direct Object Reference allows unauthorized access to other users' data or functionality.",
		"auth":      "Authentication vulnerabilities can lead to unauthorized access to user accounts and sensitive functionality.",
		"lfi":       "Local File Inclusion can expose sensitive configuration files, source code, and potentially lead to code execution.",
	}
	
	for key, impact := range impacts {
		if strings.Contains(strings.ToLower(f.VulnType), key) {
			return impact
		}
	}
	
	return "This vulnerability could lead to unauthorized access or data exposure."
}

// generateRemediation generates remediation advice
func (g *Generator) generateRemediation(f *types.Finding) string {
	remediations := map[string]string{
		"sqli": "Use parameterized queries/prepared statements. Implement input validation and output encoding.",
		"xss":  "Implement proper output encoding. Use Content-Security-Policy headers. Validate and sanitize input.",
		"ssrf": "Validate and whitelist allowed URLs. Block requests to internal IP ranges. Use network segmentation.",
		"rce":  "Avoid executing user-controlled input. Implement strict input validation. Use sandboxing.",
		"idor": "Implement proper access controls. Use indirect references. Validate authorization for each request.",
		"auth": "Implement multi-factor authentication. Use secure session management. Follow OWASP authentication guidelines.",
		"lfi":  "Avoid passing user input to file functions. Implement input validation. Use whitelists for file access.",
	}
	
	for key, remediation := range remediations {
		if strings.Contains(strings.ToLower(f.VulnType), key) {
			return remediation
		}
	}
	
	return "Review and address the identified vulnerability. Implement appropriate security controls."
}

// getReferences returns relevant references
func (g *Generator) getReferences(f *types.Finding) []string {
	refs := []string{}
	
	if f.CWE != "" {
		refs = append(refs, fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(f.CWE, "CWE-")))
	}
	if f.OWASP != "" {
		refs = append(refs, "https://owasp.org/www-project-web-security-testing-guide/")
	}
	
	return refs
}

// generateMarkdown creates Markdown report
func (g *Generator) generateMarkdown(report *Report) string {
	var md strings.Builder
	
	md.WriteString(fmt.Sprintf("# %s\n\n", report.Title))
	md.WriteString(fmt.Sprintf("**Target:** %s\n", report.Target))
	md.WriteString(fmt.Sprintf("**Generated:** %s\n\n", report.GeneratedAt.Format(time.RFC1123)))
	
	// Executive Summary
	md.WriteString("## Executive Summary\n\n")
	md.WriteString(fmt.Sprintf("This security assessment identified **%d** findings.\n\n", report.Summary.TotalFindings))
	
	md.WriteString("| Severity | Count |\n|----------|-------|\n")
	for sev, count := range report.Summary.BySeverity {
		md.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
	}
	md.WriteString("\n")
	
	// Findings
	md.WriteString("## Findings\n\n")
	
	for i, f := range report.Findings {
		md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
		md.WriteString(fmt.Sprintf("**Severity:** %s | **Type:** %s | **State:** %s\n\n", f.Severity, f.VulnType, f.State))
		md.WriteString(fmt.Sprintf("**Endpoint:** `%s`\n\n", f.Endpoint))
		md.WriteString(fmt.Sprintf("#### Description\n%s\n\n", f.Description))
		md.WriteString(fmt.Sprintf("#### Impact\n%s\n\n", f.Impact))
		md.WriteString(fmt.Sprintf("#### Remediation\n%s\n\n", f.Remediation))
		
		if f.PoC != nil {
			md.WriteString("#### Proof of Concept\n")
			md.WriteString("```\n")
			md.WriteString(f.PoC.CurlCommand)
			md.WriteString("\n```\n\n")
		}
		
		md.WriteString("---\n\n")
	}
	
	// Methodology
	md.WriteString(report.Methodology)
	
	return md.String()
}

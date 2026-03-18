// Package workspace manages bounty program directories
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Manager handles workspace creation and management
type Manager struct {
	baseDir string
}

// Workspace represents a bounty program workspace
type Workspace struct {
	Name        string
	Path        string
	CreatedAt   time.Time
	Directories map[string]string
}

// NewManager creates a new workspace manager
func NewManager(baseDir string) *Manager {
	if baseDir == "" {
		home, _ := os.UserHomeDir()
		baseDir = filepath.Join(home, "bounty-programs")
	}
	os.MkdirAll(baseDir, 0755)
	return &Manager{baseDir: baseDir}
}

// Create creates a new workspace for a bounty program
func (m *Manager) Create(programName string) (*Workspace, error) {
	// Sanitize program name for filesystem
	safeName := sanitizeName(programName)
	workspacePath := filepath.Join(m.baseDir, fmt.Sprintf("bounty-%s", safeName))
	
	// Create base directory
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}
	
	// Create standard directories
	dirs := map[string]string{
		"recon":        filepath.Join(workspacePath, "recon"),
		"recon/subs":   filepath.Join(workspacePath, "recon", "subdomains"),
		"recon/urls":   filepath.Join(workspacePath, "recon", "urls"),
		"recon/techs":  filepath.Join(workspacePath, "recon", "technologies"),
		"recon/ports":  filepath.Join(workspacePath, "recon", "ports"),
		"findings":     filepath.Join(workspacePath, "findings"),
		"findings/raw": filepath.Join(workspacePath, "findings", "raw"),
		"findings/verified": filepath.Join(workspacePath, "findings", "verified"),
		"evidence":     filepath.Join(workspacePath, "evidence"),
		"evidence/screenshots": filepath.Join(workspacePath, "evidence", "screenshots"),
		"evidence/har": filepath.Join(workspacePath, "evidence", "har"),
		"evidence/videos": filepath.Join(workspacePath, "evidence", "videos"),
		"reports":      filepath.Join(workspacePath, "reports"),
		"reports/draft": filepath.Join(workspacePath, "reports", "draft"),
		"reports/final": filepath.Join(workspacePath, "reports", "final"),
		"notes":        filepath.Join(workspacePath, "notes"),
		"tools":        filepath.Join(workspacePath, "tools"),
		"tools/output": filepath.Join(workspacePath, "tools", "output"),
		"tools/custom": filepath.Join(workspacePath, "tools", "custom"),
		"logs":         filepath.Join(workspacePath, "logs"),
		"poc":          filepath.Join(workspacePath, "poc"),
	}
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	
	ws := &Workspace{
		Name:        programName,
		Path:        workspacePath,
		CreatedAt:   time.Now(),
		Directories: dirs,
	}
	
	// Create workspace metadata file
	if err := m.saveMetadata(ws); err != nil {
		return nil, err
	}
	
	// Create initial files
	if err := m.createInitialFiles(ws); err != nil {
		return nil, err
	}
	
	return ws, nil
}

// Get returns an existing workspace
func (m *Manager) Get(programName string) (*Workspace, error) {
	safeName := sanitizeName(programName)
	workspacePath := filepath.Join(m.baseDir, fmt.Sprintf("bounty-%s", safeName))
	
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace not found: %s", programName)
	}
	
	return m.loadMetadata(workspacePath)
}

// List returns all workspaces
func (m *Manager) List() ([]*Workspace, error) {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return nil, err
	}
	
	var workspaces []*Workspace
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) > 7 && entry.Name()[:7] == "bounty-" {
			path := filepath.Join(m.baseDir, entry.Name())
			if ws, err := m.loadMetadata(path); err == nil {
				workspaces = append(workspaces, ws)
			}
		}
	}
	
	return workspaces, nil
}

// GetPath returns the path for a specific type of file
func (ws *Workspace) GetPath(category string) string {
	if path, ok := ws.Directories[category]; ok {
		return path
	}
	return ws.Path
}

// GetReconPath returns the recon directory
func (ws *Workspace) GetReconPath() string {
	return ws.Directories["recon"]
}

// GetFindingsPath returns the findings directory
func (ws *Workspace) GetFindingsPath() string {
	return ws.Directories["findings"]
}

// GetEvidencePath returns the evidence directory
func (ws *Workspace) GetEvidencePath() string {
	return ws.Directories["evidence"]
}

// GetReportsPath returns the reports directory
func (ws *Workspace) GetReportsPath() string {
	return ws.Directories["reports"]
}

// createInitialFiles creates template files in the workspace
func (m *Manager) createInitialFiles(ws *Workspace) error {
	// Create README
	readme := fmt.Sprintf(`# Bounty Program: %s

Created: %s

## Directory Structure

- **recon/** - Reconnaissance data (subdomains, URLs, technologies)
- **findings/** - Discovered vulnerabilities (raw and verified)
- **evidence/** - Screenshots, HAR files, videos
- **reports/** - Draft and final reports
- **notes/** - Manual notes and observations
- **tools/** - Tool output and custom scripts
- **logs/** - Execution logs
- **poc/** - Proof of concept files

## Status

- [ ] Recon complete
- [ ] Initial scan complete
- [ ] Manual testing complete
- [ ] Report drafted
- [ ] Report submitted

`, ws.Name, ws.CreatedAt.Format(time.RFC1123))
	
	if err := os.WriteFile(filepath.Join(ws.Path, "README.md"), []byte(readme), 0644); err != nil {
		return err
	}
	
	// Create scope.txt template
	scope := `# Scope

## In Scope


## Out of Scope


## Rules

`
	if err := os.WriteFile(filepath.Join(ws.Path, "scope.txt"), []byte(scope), 0644); err != nil {
		return err
	}
	
	// Create notes template
	notes := fmt.Sprintf(`# Notes - %s

## Session Log

### %s
- Started testing

## Interesting Findings


## Questions to Investigate


## Ideas

`, ws.Name, time.Now().Format("2006-01-02"))
	
	if err := os.WriteFile(filepath.Join(ws.Directories["notes"], "notes.md"), []byte(notes), 0644); err != nil {
		return err
	}
	
	return nil
}

// saveMetadata saves workspace metadata
func (m *Manager) saveMetadata(ws *Workspace) error {
	metadata := fmt.Sprintf(`{
  "name": "%s",
  "path": "%s",
  "created_at": "%s"
}`, ws.Name, ws.Path, ws.CreatedAt.Format(time.RFC3339))
	
	return os.WriteFile(filepath.Join(ws.Path, ".workspace.json"), []byte(metadata), 0644)
}

// loadMetadata loads workspace metadata
func (m *Manager) loadMetadata(path string) (*Workspace, error) {
	data, err := os.ReadFile(filepath.Join(path, ".workspace.json"))
	if err != nil {
		// Create minimal workspace from directory
		return &Workspace{
			Name: filepath.Base(path),
			Path: path,
			Directories: map[string]string{
				"recon":    filepath.Join(path, "recon"),
				"findings": filepath.Join(path, "findings"),
				"evidence": filepath.Join(path, "evidence"),
				"reports":  filepath.Join(path, "reports"),
			},
		}, nil
	}
	
	// Parse JSON (simplified)
	_ = data
	return &Workspace{
		Name: filepath.Base(path),
		Path: path,
		Directories: map[string]string{
			"recon":    filepath.Join(path, "recon"),
			"findings": filepath.Join(path, "findings"),
			"evidence": filepath.Join(path, "evidence"),
			"reports":  filepath.Join(path, "reports"),
			"notes":    filepath.Join(path, "notes"),
			"tools":    filepath.Join(path, "tools"),
			"logs":     filepath.Join(path, "logs"),
			"poc":      filepath.Join(path, "poc"),
		},
	}, nil
}

// sanitizeName makes a name filesystem-safe
func sanitizeName(name string) string {
	safe := ""
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
		   (r >= '0' && r <= '9') || r == '-' || r == '_' {
			safe += string(r)
		} else if r == ' ' {
			safe += "-"
		}
	}
	return safe
}

// AddFinding saves a finding to the workspace
func (ws *Workspace) AddFinding(id, title, severity string, verified bool) (string, error) {
	dir := ws.Directories["findings/raw"]
	if verified {
		dir = ws.Directories["findings/verified"]
	}
	
	filename := fmt.Sprintf("%s-%s.md", severity, id)
	path := filepath.Join(dir, filename)
	
	content := fmt.Sprintf(`# %s

**ID:** %s
**Severity:** %s
**Verified:** %v
**Date:** %s

## Description


## Impact


## Steps to Reproduce


## Proof of Concept


## Evidence


## Remediation

`, title, id, severity, verified, time.Now().Format(time.RFC3339))
	
	return path, os.WriteFile(path, []byte(content), 0644)
}

// SaveToolOutput saves tool output to the workspace
func (ws *Workspace) SaveToolOutput(toolName, target string, output []byte) (string, error) {
	dir := filepath.Join(ws.Directories["tools/output"], toolName)
	os.MkdirAll(dir, 0755)
	
	filename := fmt.Sprintf("%s_%d.txt", sanitizeName(target), time.Now().Unix())
	path := filepath.Join(dir, filename)
	
	return path, os.WriteFile(path, output, 0644)
}

// SaveEvidence saves evidence to the workspace
func (ws *Workspace) SaveEvidence(evidenceType, findingID string, data []byte, ext string) (string, error) {
	var dir string
	switch evidenceType {
	case "screenshot":
		dir = ws.Directories["evidence/screenshots"]
	case "har":
		dir = ws.Directories["evidence/har"]
	case "video":
		dir = ws.Directories["evidence/videos"]
	default:
		dir = ws.Directories["evidence"]
	}
	
	filename := fmt.Sprintf("%s_%d.%s", findingID, time.Now().Unix(), ext)
	path := filepath.Join(dir, filename)
	
	return path, os.WriteFile(path, data, 0644)
}

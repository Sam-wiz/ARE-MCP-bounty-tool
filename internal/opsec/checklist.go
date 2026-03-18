package opsec

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Checklist represents a risky operation checklist
type Checklist struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Requires    Requires `yaml:"requires"`
	OpsecLayers []string `yaml:"opsec_layers"`
	Items       []string `yaml:"checklist"`
}

// Requires specifies requirements for an operation
type Requires struct {
	ExplicitPermission bool `yaml:"explicit_permission"`
	ScopeConfirmation  bool `yaml:"scope_confirmation"`
	FindingVerified    bool `yaml:"finding_verified"`
}

// ChecklistManager manages risky operation checklists
type ChecklistManager struct {
	checklists map[string]*Checklist
	opsecMgr   *Manager
}

// NewChecklistManager creates a new checklist manager
func NewChecklistManager(configPath string, opsecMgr *Manager) (*ChecklistManager, error) {
	cm := &ChecklistManager{
		checklists: make(map[string]*Checklist),
		opsecMgr:   opsecMgr,
	}
	
	if err := cm.loadChecklists(configPath); err != nil {
		return nil, err
	}
	
	return cm, nil
}

// loadChecklists loads checklists from YAML file
func (cm *ChecklistManager) loadChecklists(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	
	var config struct {
		Operations []Checklist `yaml:"operations"`
	}
	
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}
	
	for i := range config.Operations {
		cm.checklists[config.Operations[i].Name] = &config.Operations[i]
	}
	
	return nil
}

// GetChecklist returns a checklist by name
func (cm *ChecklistManager) GetChecklist(name string) (*Checklist, bool) {
	cl, ok := cm.checklists[name]
	return cl, ok
}

// ValidateOperation validates if an operation can proceed
func (cm *ChecklistManager) ValidateOperation(name string, context *OperationContext) (*ValidationResult, error) {
	checklist, ok := cm.checklists[name]
	if !ok {
		return nil, fmt.Errorf("unknown operation: %s", name)
	}
	
	result := &ValidationResult{
		Operation:  name,
		CanProceed: true,
		Warnings:   make([]string, 0),
		Blockers:   make([]string, 0),
	}
	
	// Check requirements
	if checklist.Requires.ExplicitPermission && !context.HasExplicitPermission {
		result.CanProceed = false
		result.Blockers = append(result.Blockers, "Explicit permission required from human operator")
	}
	
	if checklist.Requires.ScopeConfirmation && !context.ScopeConfirmed {
		result.CanProceed = false
		result.Blockers = append(result.Blockers, "Scope confirmation required")
	}
	
	if checklist.Requires.FindingVerified && !context.FindingVerified {
		result.CanProceed = false
		result.Blockers = append(result.Blockers, "Finding must be verified before this operation")
	}
	
	// Check OPSEC requirements
	if cm.opsecMgr != nil && !cm.opsecMgr.IsVerified() {
		for _, layer := range checklist.OpsecLayers {
			result.Warnings = append(result.Warnings, 
				fmt.Sprintf("OPSEC layer '%s' should be active", layer))
		}
	}
	
	// Generate checklist items for display
	result.ChecklistItems = checklist.Items
	
	return result, nil
}

// RequestApproval requests human approval for a risky operation
func (cm *ChecklistManager) RequestApproval(name string, context *OperationContext) *ApprovalRequest {
	checklist, ok := cm.checklists[name]
	if !ok {
		return nil
	}
	
	return &ApprovalRequest{
		Operation:   name,
		Description: checklist.Description,
		Checklist:   checklist.Items,
		Context:     context,
		Urgency:     "blocking",
	}
}

// OperationContext provides context for an operation
type OperationContext struct {
	HasExplicitPermission bool
	ScopeConfirmed        bool
	FindingVerified       bool
	Target                string
	FindingID             string
	Details               map[string]interface{}
}

// ValidationResult holds validation results
type ValidationResult struct {
	Operation      string   `json:"operation"`
	CanProceed     bool     `json:"can_proceed"`
	Warnings       []string `json:"warnings"`
	Blockers       []string `json:"blockers"`
	ChecklistItems []string `json:"checklist_items"`
}

// ApprovalRequest represents a request for human approval
type ApprovalRequest struct {
	Operation   string                 `json:"operation"`
	Description string                 `json:"description"`
	Checklist   []string               `json:"checklist"`
	Context     *OperationContext      `json:"context"`
	Urgency     string                 `json:"urgency"` // blocking, warning
}

// FormatForDisplay formats the approval request for display
func (ar *ApprovalRequest) FormatForDisplay() string {
	result := fmt.Sprintf(`
🔒 RISKY OPERATION APPROVAL REQUIRED

Operation: %s
Description: %s
Target: %s

CHECKLIST:
`, ar.Operation, ar.Description, ar.Context.Target)
	
	for i, item := range ar.Checklist {
		result += fmt.Sprintf("  [ ] %d. %s\n", i+1, item)
	}
	
	result += `
⚠️  This operation requires explicit approval.
Please review the checklist and confirm to proceed.
`
	return result
}

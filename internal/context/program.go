// Package context manages persistent program context
package context

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// ProgramContext stores the complete bug bounty program details
// This is persisted to MongoDB to prevent "forgetting" program info
type ProgramContext struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Platform    string             `bson:"platform" json:"platform"` // hackerone, bugcrowd, intigriti, etc.
	URL         string             `bson:"url" json:"url"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
	
	// Core scope information - NEVER forget these
	Scope       ScopeDetails       `bson:"scope" json:"scope"`
	Rules       ProgramRules       `bson:"rules" json:"rules"`
	Rewards     RewardStructure    `bson:"rewards" json:"rewards"`
	
	// Session state
	WorkspacePath string           `bson:"workspace_path" json:"workspace_path"`
	ActiveSession string           `bson:"active_session" json:"active_session"`
	
	// Tracking
	Findings    []string           `bson:"findings" json:"findings"` // Finding IDs
	ToolsRun    []ToolRunRecord    `bson:"tools_run" json:"tools_run"`
}

// ScopeDetails captures what's in and out of scope
type ScopeDetails struct {
	// In-scope targets
	InScopeDomains     []string `bson:"in_scope_domains" json:"in_scope_domains"`
	InScopeIPs         []string `bson:"in_scope_ips" json:"in_scope_ips"`
	InScopeApps        []string `bson:"in_scope_apps" json:"in_scope_apps"`
	InScopeAPIs        []string `bson:"in_scope_apis" json:"in_scope_apis"`
	InScopeWildcards   []string `bson:"in_scope_wildcards" json:"in_scope_wildcards"`
	
	// Out of scope - CRITICAL to remember
	OutOfScopeDomains  []string `bson:"out_of_scope_domains" json:"out_of_scope_domains"`
	OutOfScopeIPs      []string `bson:"out_of_scope_ips" json:"out_of_scope_ips"`
	OutOfScopeVulns    []string `bson:"out_of_scope_vulns" json:"out_of_scope_vulns"`
	
	// Vulnerability focus
	VulnTypesInScope   []string `bson:"vuln_types_in_scope" json:"vuln_types_in_scope"`
	VulnTypesExcluded  []string `bson:"vuln_types_excluded" json:"vuln_types_excluded"`
	
	// Raw scope text (for reference)
	RawScopeText       string   `bson:"raw_scope_text" json:"raw_scope_text"`
}

// ProgramRules captures testing rules and restrictions
type ProgramRules struct {
	// Rate limiting
	MaxRequestsPerSecond int    `bson:"max_rps" json:"max_rps"`
	RateLimitNotes       string `bson:"rate_limit_notes" json:"rate_limit_notes"`
	
	// Testing restrictions
	NoAutoScanning       bool   `bson:"no_auto_scanning" json:"no_auto_scanning"`
	NoDoS                bool   `bson:"no_dos" json:"no_dos"`
	NoPhysicalAccess     bool   `bson:"no_physical" json:"no_physical"`
	NoSocialEngineering  bool   `bson:"no_social_eng" json:"no_social_eng"`
	NoDNSExfiltration    bool   `bson:"no_dns_exfil" json:"no_dns_exfil"`
	
	// Reporting requirements
	RequiresPOC          bool   `bson:"requires_poc" json:"requires_poc"`
	RequiresVideo        bool   `bson:"requires_video" json:"requires_video"`
	RequiresImpact       bool   `bson:"requires_impact" json:"requires_impact"`
	
	// Special notes
	SpecialInstructions  string `bson:"special_instructions" json:"special_instructions"`
	
	// Raw rules text
	RawRulesText         string `bson:"raw_rules_text" json:"raw_rules_text"`
}

// RewardStructure captures payout information
type RewardStructure struct {
	CriticalMin  int    `bson:"critical_min" json:"critical_min"`
	CriticalMax  int    `bson:"critical_max" json:"critical_max"`
	HighMin      int    `bson:"high_min" json:"high_min"`
	HighMax      int    `bson:"high_max" json:"high_max"`
	MediumMin    int    `bson:"medium_min" json:"medium_min"`
	MediumMax    int    `bson:"medium_max" json:"medium_max"`
	LowMin       int    `bson:"low_min" json:"low_min"`
	LowMax       int    `bson:"low_max" json:"low_max"`
	Currency     string `bson:"currency" json:"currency"`
	BonusProgram bool   `bson:"bonus_program" json:"bonus_program"`
}

// ToolRunRecord tracks what tools have been run
type ToolRunRecord struct {
	Tool      string    `bson:"tool" json:"tool"`
	Target    string    `bson:"target" json:"target"`
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`
	Status    string    `bson:"status" json:"status"`
}

// Manager handles program context persistence
type Manager struct {
	collection *mongo.Collection
	localPath  string // Fallback local storage
}

// NewManager creates a new context manager
func NewManager(db *mongo.Database, localPath string) *Manager {
	var collection *mongo.Collection
	if db != nil {
		collection = db.Collection("program_contexts")
	}
	return &Manager{
		collection: collection,
		localPath:  localPath,
	}
}

// Create creates a new program context
func (m *Manager) Create(ctx context.Context, program *ProgramContext) error {
	program.CreatedAt = time.Now()
	program.UpdatedAt = time.Now()
	
	// Store in MongoDB
	if m.collection != nil {
		result, err := m.collection.InsertOne(ctx, program)
		if err != nil {
			return err
		}
		program.ID = result.InsertedID.(primitive.ObjectID)
	}
	
	// Also save locally for offline access
	return m.saveLocal(program)
}

// Get retrieves a program context by name
func (m *Manager) Get(ctx context.Context, name string) (*ProgramContext, error) {
	// Try MongoDB first
	if m.collection != nil {
		var program ProgramContext
		err := m.collection.FindOne(ctx, bson.M{"name": name}).Decode(&program)
		if err == nil {
			return &program, nil
		}
	}
	
	// Fall back to local
	return m.loadLocal(name)
}

// GetByID retrieves by MongoDB ID
func (m *Manager) GetByID(ctx context.Context, id string) (*ProgramContext, error) {
	if m.collection == nil {
		return nil, fmt.Errorf("MongoDB not available")
	}
	
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	
	var program ProgramContext
	err = m.collection.FindOne(ctx, bson.M{"_id": oid}).Decode(&program)
	return &program, err
}

// Update updates an existing program context
func (m *Manager) Update(ctx context.Context, program *ProgramContext) error {
	program.UpdatedAt = time.Now()
	
	if m.collection != nil {
		_, err := m.collection.ReplaceOne(ctx, bson.M{"_id": program.ID}, program)
		if err != nil {
			return err
		}
	}
	
	return m.saveLocal(program)
}

// List lists all program contexts
func (m *Manager) List(ctx context.Context) ([]*ProgramContext, error) {
	if m.collection != nil {
		cursor, err := m.collection.Find(ctx, bson.M{})
		if err != nil {
			return nil, err
		}
		defer cursor.Close(ctx)
		
		var programs []*ProgramContext
		if err := cursor.All(ctx, &programs); err != nil {
			return nil, err
		}
		return programs, nil
	}
	
	// Fall back to local
	return m.listLocal()
}

// GetContextSummary returns a summary for LLM context injection
// This is what gets injected at the start of each tool execution
func (m *Manager) GetContextSummary(program *ProgramContext) string {
	summary := fmt.Sprintf(`
=== PROGRAM CONTEXT: %s ===
Platform: %s
URL: %s

=== IN SCOPE ===
Domains: %v
Wildcards: %v
IPs: %v
Apps: %v

=== OUT OF SCOPE (DO NOT TEST) ===
Domains: %v
IPs: %v
Vuln Types: %v

=== RULES ===
Max RPS: %d
No Auto Scanning: %v
No DoS: %v
Special: %s

=== CURRENT STATE ===
Workspace: %s
Findings: %d
Tools Run: %d
===
`,
		program.Name,
		program.Platform,
		program.URL,
		program.Scope.InScopeDomains,
		program.Scope.InScopeWildcards,
		program.Scope.InScopeIPs,
		program.Scope.InScopeApps,
		program.Scope.OutOfScopeDomains,
		program.Scope.OutOfScopeIPs,
		program.Scope.OutOfScopeVulns,
		program.Rules.MaxRequestsPerSecond,
		program.Rules.NoAutoScanning,
		program.Rules.NoDoS,
		program.Rules.SpecialInstructions,
		program.WorkspacePath,
		len(program.Findings),
		len(program.ToolsRun),
	)
	return summary
}

// IsInScope checks if a target is in scope
func (m *Manager) IsInScope(program *ProgramContext, target string) (bool, string) {
	// Check out of scope first (takes priority)
	for _, domain := range program.Scope.OutOfScopeDomains {
		if matchesDomain(target, domain) {
			return false, fmt.Sprintf("Target matches out-of-scope domain: %s", domain)
		}
	}
	
	// Check in scope
	for _, domain := range program.Scope.InScopeDomains {
		if matchesDomain(target, domain) {
			return true, "Matches in-scope domain"
		}
	}
	
	for _, wildcard := range program.Scope.InScopeWildcards {
		if matchesWildcard(target, wildcard) {
			return true, "Matches in-scope wildcard"
		}
	}
	
	return false, "Target not found in scope"
}

// RecordToolRun records a tool execution
func (m *Manager) RecordToolRun(ctx context.Context, program *ProgramContext, tool, target, status string) error {
	record := ToolRunRecord{
		Tool:      tool,
		Target:    target,
		Timestamp: time.Now(),
		Status:    status,
	}
	program.ToolsRun = append(program.ToolsRun, record)
	return m.Update(ctx, program)
}

// Local storage functions
func (m *Manager) saveLocal(program *ProgramContext) error {
	if m.localPath == "" {
		return nil
	}
	
	dir := filepath.Join(m.localPath, "contexts")
	os.MkdirAll(dir, 0755)
	
	data, err := json.MarshalIndent(program, "", "  ")
	if err != nil {
		return err
	}
	
	filename := filepath.Join(dir, fmt.Sprintf("%s.json", program.Name))
	return os.WriteFile(filename, data, 0644)
}

func (m *Manager) loadLocal(name string) (*ProgramContext, error) {
	filename := filepath.Join(m.localPath, "contexts", fmt.Sprintf("%s.json", name))
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	var program ProgramContext
	if err := json.Unmarshal(data, &program); err != nil {
		return nil, err
	}
	
	return &program, nil
}

func (m *Manager) listLocal() ([]*ProgramContext, error) {
	dir := filepath.Join(m.localPath, "contexts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	
	var programs []*ProgramContext
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			name := entry.Name()[:len(entry.Name())-5]
			program, err := m.loadLocal(name)
			if err == nil {
				programs = append(programs, program)
			}
		}
	}
	
	return programs, nil
}

// Helper functions
func matchesDomain(target, domain string) bool {
	return target == domain || 
		   (len(target) > len(domain) && target[len(target)-len(domain)-1:] == "."+domain)
}

func matchesWildcard(target, wildcard string) bool {
	if len(wildcard) > 2 && wildcard[:2] == "*." {
		suffix := wildcard[1:] // .domain.com
		return len(target) > len(suffix) && target[len(target)-len(suffix):] == suffix
	}
	return target == wildcard
}

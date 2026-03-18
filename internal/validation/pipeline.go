// Package validation implements the finding validation pipeline
package validation

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// Pipeline manages the validation workflow for findings
type Pipeline struct {
	executors map[string]PoCExecutor
	evidence  *EvidenceCollector
	mu        sync.RWMutex
}

// PoCExecutor interface for different PoC execution strategies
type PoCExecutor interface {
	// CanHandle checks if this executor can handle the finding type
	CanHandle(finding *types.Finding) bool
	// Verify runs secondary verification
	Verify(ctx context.Context, finding *types.Finding) (*VerifyResult, error)
	// GeneratePoC creates a proof of concept
	GeneratePoC(ctx context.Context, finding *types.Finding) (*types.PoC, error)
	// ExecutePoC runs the proof of concept
	ExecutePoC(ctx context.Context, poc *types.PoC) (*ExecuteResult, error)
}

// VerifyResult holds verification results
type VerifyResult struct {
	Verified    bool
	Confidence  float64 // 0.0 - 1.0
	Method      string
	Details     string
	SecondaryID string // ID of secondary tool used
}

// ExecuteResult holds PoC execution results
type ExecuteResult struct {
	Success     bool
	Impact      string
	Evidence    []string // Paths to evidence files
	Response    string   // Raw response if applicable
	Screenshot  string   // Screenshot path if applicable
	VideoPath   string   // Video recording path if applicable
	ExecutionMs int64
}

// NewPipeline creates a new validation pipeline
func NewPipeline(evidenceDir string) *Pipeline {
	p := &Pipeline{
		executors: make(map[string]PoCExecutor),
		evidence:  NewEvidenceCollector(evidenceDir),
	}

	// Register default executors
	p.RegisterExecutor("http", NewHTTPExecutor())
	p.RegisterExecutor("browser", NewBrowserExecutor())
	p.RegisterExecutor("injection", NewInjectionExecutor())

	return p
}

// RegisterExecutor adds an executor to the pipeline
func (p *Pipeline) RegisterExecutor(name string, executor PoCExecutor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.executors[name] = executor
}

// Process runs a finding through the validation pipeline
func (p *Pipeline) Process(ctx context.Context, finding *types.Finding, level int) error {
	log.Printf("Processing finding %s through validation pipeline (level %d)", finding.ID, level)

	// Find appropriate executor
	executor := p.findExecutor(finding)
	if executor == nil {
		finding.State = types.FindingManualRequired
		finding.ManualReason = "No suitable PoC executor available"
		return fmt.Errorf("no executor found for finding type: %s", finding.VulnType)
	}

	// Level 2+: Verify
	if level >= 2 {
		if err := p.runVerification(ctx, finding, executor); err != nil {
			return err
		}
	}

	// Level 3: Generate and Execute PoC
	if level >= 3 && finding.State == types.FindingVerified {
		if err := p.runPoCExecution(ctx, finding, executor); err != nil {
			return err
		}
	}

	// Capture evidence for successful exploitation
	if finding.State == types.FindingExploited {
		if err := p.captureEvidence(ctx, finding); err != nil {
			log.Printf("Warning: Failed to capture evidence: %v", err)
		}
	}

	return nil
}

// findExecutor finds an appropriate executor for the finding
func (p *Pipeline) findExecutor(finding *types.Finding) PoCExecutor {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, executor := range p.executors {
		if executor.CanHandle(finding) {
			return executor
		}
	}
	return nil
}

// runVerification performs secondary verification
func (p *Pipeline) runVerification(ctx context.Context, finding *types.Finding, executor PoCExecutor) error {
	log.Printf("Running verification for %s", finding.ID)

	result, err := executor.Verify(ctx, finding)
	if err != nil {
		finding.State = types.FindingManualRequired
		finding.ManualReason = fmt.Sprintf("Verification failed: %v", err)
		return err
	}

	if result.Verified && result.Confidence >= 0.7 {
		finding.State = types.FindingVerified
		finding.Verification = &types.Verification{
			Status:     "verified",
			Method:     result.Method,
			Confidence: result.Confidence,
			Details:    result.Details,
			VerifiedAt: time.Now(),
		}
	} else {
		finding.State = types.FindingFalsePositive
		finding.Verification = &types.Verification{
			Status:     "false_positive",
			Method:     result.Method,
			Confidence: result.Confidence,
			Details:    result.Details,
			VerifiedAt: time.Now(),
		}
	}

	return nil
}

// runPoCExecution generates and executes proof of concept
func (p *Pipeline) runPoCExecution(ctx context.Context, finding *types.Finding, executor PoCExecutor) error {
	log.Printf("Running PoC execution for %s", finding.ID)

	// Generate PoC
	poc, err := executor.GeneratePoC(ctx, finding)
	if err != nil {
		finding.State = types.FindingManualRequired
		finding.ManualReason = fmt.Sprintf("PoC generation failed: %v", err)
		return err
	}

	finding.PoC = poc
	finding.State = types.FindingPoCReady

	// Execute PoC
	result, err := executor.ExecutePoC(ctx, poc)
	if err != nil {
		finding.State = types.FindingManualRequired
		finding.ManualReason = fmt.Sprintf("PoC execution failed: %v", err)
		return err
	}

	if result.Success {
		finding.State = types.FindingExploited
		finding.Evidence = append(finding.Evidence, result.Evidence...)
		if result.Screenshot != "" {
			finding.Evidence = append(finding.Evidence, result.Screenshot)
		}
	} else {
		finding.State = types.FindingManualRequired
		finding.ManualReason = "PoC executed but exploitation unsuccessful"
	}

	return nil
}

// captureEvidence captures additional evidence for the finding
func (p *Pipeline) captureEvidence(ctx context.Context, finding *types.Finding) error {
	log.Printf("Capturing evidence for %s", finding.ID)

	// Capture screenshot
	if screenshot, err := p.evidence.CaptureScreenshot(ctx, finding.URL); err == nil {
		finding.Evidence = append(finding.Evidence, screenshot)
	}

	// Capture HAR if HTTP-based
	if har, err := p.evidence.CaptureHAR(ctx, finding.URL); err == nil {
		finding.Evidence = append(finding.Evidence, har)
	}

	return nil
}

// StateTransition represents a valid state transition
type StateTransition struct {
	From   types.FindingState
	To     types.FindingState
	Action string
}

// ValidTransitions defines allowed state transitions
var ValidTransitions = []StateTransition{
	{types.FindingDetected, types.FindingVerified, "verification_passed"},
	{types.FindingDetected, types.FindingFalsePositive, "verification_failed"},
	{types.FindingDetected, types.FindingManualRequired, "verification_error"},
	{types.FindingVerified, types.FindingPoCReady, "poc_generated"},
	{types.FindingVerified, types.FindingManualRequired, "poc_generation_failed"},
	{types.FindingPoCReady, types.FindingExploited, "poc_successful"},
	{types.FindingPoCReady, types.FindingManualRequired, "poc_failed"},
}

// CanTransition checks if a state transition is valid
func CanTransition(from, to types.FindingState) bool {
	for _, t := range ValidTransitions {
		if t.From == from && t.To == to {
			return true
		}
	}
	return false
}

package validation

import (
	"context"
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

func TestCanTransition_ValidTransitions(t *testing.T) {
	tests := []struct {
		from types.FindingState
		to   types.FindingState
		ok   bool
	}{
		{types.FindingDetected, types.FindingVerified, true},
		{types.FindingDetected, types.FindingFalsePositive, true},
		{types.FindingDetected, types.FindingManualRequired, true},
		{types.FindingVerified, types.FindingPoCReady, true},
		{types.FindingVerified, types.FindingManualRequired, true},
		{types.FindingPoCReady, types.FindingExploited, true},
		{types.FindingPoCReady, types.FindingManualRequired, true},
	}

	for _, tt := range tests {
		result := CanTransition(tt.from, tt.to)
		if result != tt.ok {
			t.Errorf("CanTransition(%s, %s) = %v, want %v", tt.from, tt.to, result, tt.ok)
		}
	}
}

func TestCanTransition_InvalidTransitions(t *testing.T) {
	tests := []struct {
		from types.FindingState
		to   types.FindingState
	}{
		{types.FindingVerified, types.FindingDetected},           // can't go back
		{types.FindingExploited, types.FindingDetected},          // can't go back
		{types.FindingFalsePositive, types.FindingVerified},      // false positive is terminal
		{types.FindingDetected, types.FindingExploited},          // can't skip
		{types.FindingDetected, types.FindingPoCReady},           // can't skip
	}

	for _, tt := range tests {
		if CanTransition(tt.from, tt.to) {
			t.Errorf("CanTransition(%s, %s) should be false but was true", tt.from, tt.to)
		}
	}
}

func TestNewPipeline(t *testing.T) {
	p := NewPipeline("/tmp/evidence")
	if p == nil {
		t.Fatal("NewPipeline returned nil")
	}
	if len(p.executors) == 0 {
		t.Error("Pipeline has no default executors")
	}
}

func TestPipeline_RegisterExecutor(t *testing.T) {
	p := NewPipeline("/tmp/evidence")
	initialCount := len(p.executors)

	// Register a mock executor
	p.RegisterExecutor("custom", &mockExecutor{})

	if len(p.executors) != initialCount+1 {
		t.Errorf("Expected %d executors, got %d", initialCount+1, len(p.executors))
	}
}

func TestPipeline_FindExecutor_NoMatch(t *testing.T) {
	p := &Pipeline{
		executors: make(map[string]PoCExecutor),
	}

	finding := &types.Finding{
		VulnType: "unknown-type",
	}

	executor := p.findExecutor(finding)
	if executor != nil {
		t.Error("Expected nil executor for unknown type")
	}
}

// mockExecutor for testing
type mockExecutor struct{}

func (m *mockExecutor) CanHandle(f *types.Finding) bool                                              { return false }
func (m *mockExecutor) Verify(ctx context.Context, f *types.Finding) (*VerifyResult, error)          { return nil, nil }
func (m *mockExecutor) GeneratePoC(ctx context.Context, f *types.Finding) (*types.PoC, error)        { return nil, nil }
func (m *mockExecutor) ExecutePoC(ctx context.Context, poc *types.PoC) (*ExecuteResult, error)       { return nil, nil }

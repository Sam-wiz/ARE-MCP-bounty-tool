package core

import (
	"context"
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

func TestFindingsStayWithinActiveProgram(t *testing.T) {
	cfg := config.LoadOrDefault("")
	cfg.Workspace.BaseDir = t.TempDir()
	e := NewEngine(EngineConfig{Config: cfg})
	e.program = "one"
	e.findings = map[string]*types.Finding{
		"a": {ID: "a", Program: "one", Severity: "high"},
		"b": {ID: "b", Program: "two", Severity: "high"},
		"c": {ID: "c", Program: "one", Severity: "info"},
	}
	findings, err := e.findingsForProgram(context.Background(), map[string]interface{}{"severity": "high"})
	if err != nil || len(findings) != 1 || findings[0].ID != "a" {
		t.Fatalf("program/filter isolation failed: %v %v", findings, err)
	}
}
func TestProgramSwitchClearsPriorSessionAndScope(t *testing.T) {
	t.Setenv("WORKSPACE_SKIP_VENV", "1")
	cfg := config.LoadOrDefault("")
	cfg.Workspace.BaseDir = t.TempDir()
	e := NewEngine(EngineConfig{Config: cfg})
	e.program = "old"
	e.scope = types.Scope{InScope: []string{"old.example.test"}}
	e.session = &types.Session{ID: "old-session"}
	e.findings["old"] = &types.Finding{ID: "old", Program: "old"}
	result, err := e.handleSetProgram(context.Background(), map[string]interface{}{"slug": "new"})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	if e.session != nil || len(e.scope.InScope) != 0 || len(e.findings) != 0 {
		t.Fatal("previous program state carried into new program")
	}
}

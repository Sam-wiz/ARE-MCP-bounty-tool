package core

import (
	"context"
	"os"
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/storage"
)

// TestIntegrationPipeline tests the full: set_program → set_target → ingest_result → get_findings flow
func TestIntegrationPipeline(t *testing.T) {
	ctx := context.Background()

	// Build engine without MongoDB (unit test mode)
	config := EngineConfig{}

	// If MONGODB_URI is set, test with real MongoDB
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI != "" {
		mc, err := storage.NewMongoClient(ctx, mongoURI)
		if err != nil {
			t.Logf("MongoDB not available, running without persistence: %v", err)
		} else {
			config.MongoDB = mc
			defer mc.Close(ctx)
			t.Log("✅ MongoDB connected")
		}
	} else {
		t.Log("ℹ️  MONGODB_URI not set, testing without persistence")
	}

	engine := NewEngine(config)

	// Step 1: Set program
	t.Run("SetProgram", func(t *testing.T) {
		result, err := engine.ExecuteTool(ctx, "set_program", map[string]interface{}{
			"slug":     "test-program",
			"name":     "Test Bug Bounty Program",
			"platform": "hackerone",
			"url":      "https://hackerone.com/test",
			"payout_min": float64(100),
			"payout_max": float64(10000),
		})
		if err != nil {
			t.Fatalf("set_program failed: %v", err)
		}
		if result.IsError {
			t.Fatalf("set_program returned error: %s", result.Content[0].Text)
		}
		t.Logf("set_program: %s", result.Content[0].Text)

		// Verify program is set
		if engine.GetProgram() != "test-program" {
			t.Fatalf("expected program 'test-program', got '%s'", engine.GetProgram())
		}
	})

	// Step 2: Set target
	t.Run("SetTarget", func(t *testing.T) {
		result, err := engine.ExecuteTool(ctx, "set_target", map[string]interface{}{
			"domain": "example.com",
		})
		if err != nil {
			t.Fatalf("set_target failed: %v", err)
		}
		if result.IsError {
			t.Fatalf("set_target returned error: %s", result.Content[0].Text)
		}
		t.Logf("set_target: %s", result.Content[0].Text)

		// Verify session has program tag
		if engine.session.Program != "test-program" {
			t.Fatalf("expected session program 'test-program', got '%s'", engine.session.Program)
		}
	})

	// Step 3: Ingest finding
	t.Run("IngestResult", func(t *testing.T) {
		result, err := engine.ExecuteTool(ctx, "ingest_result", map[string]interface{}{
			"title":       "Test IDOR Vulnerability",
			"severity":    "high",
			"vuln_type":   "idor",
			"url":         "https://example.com/api/v1/users/123",
			"description": "Able to access other users' profiles by changing user ID parameter",
		})
		if err != nil {
			t.Fatalf("ingest_result failed: %v", err)
		}
		if result.IsError {
			t.Fatalf("ingest_result returned error: %s", result.Content[0].Text)
		}
		t.Logf("ingest_result: %s", result.Content[0].Text)
	})

	// Step 4: Get findings
	t.Run("GetFindings", func(t *testing.T) {
		result, err := engine.ExecuteTool(ctx, "get_findings", map[string]interface{}{})
		if err != nil {
			t.Fatalf("get_findings failed: %v", err)
		}
		if result.IsError {
			t.Fatalf("get_findings returned error: %s", result.Content[0].Text)
		}

		text := result.Content[0].Text
		if len(engine.findings) == 0 {
			t.Fatal("expected at least 1 finding")
		}

		// Verify finding has program tag
		for _, f := range engine.findings {
			if f.Program != "test-program" {
				t.Fatalf("expected finding program 'test-program', got '%s'", f.Program)
			}
		}

		t.Logf("get_findings: %s", text[:min(len(text), 200)])
	})

	// Step 5: List programs (requires MongoDB)
	if config.MongoDB != nil {
		t.Run("ListPrograms", func(t *testing.T) {
			result, err := engine.ExecuteTool(ctx, "list_programs", map[string]interface{}{})
			if err != nil {
				t.Fatalf("list_programs failed: %v", err)
			}
			t.Logf("list_programs: %s", result.Content[0].Text)
		})

		t.Run("ProgramStats", func(t *testing.T) {
			result, err := engine.ExecuteTool(ctx, "program_stats", map[string]interface{}{
				"program": "test-program",
			})
			if err != nil {
				t.Fatalf("program_stats failed: %v", err)
			}
			t.Logf("program_stats: %s", result.Content[0].Text)
		})
	}

	t.Log("✅ Integration pipeline complete")
}

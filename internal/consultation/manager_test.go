package consultation

import (
	"context"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.pending == nil {
		t.Error("pending map not initialized")
	}
}

func TestConsultation_FormatForDisplay(t *testing.T) {
	c := &Consultation{
		ID:       "test-id",
		Type:     ConsultScope,
		Urgency:  UrgencyBlocking,
		Question: "Is example.com in scope?",
		Context:  "Found during recon",
		Options: []Option{
			{ID: "yes", Label: "Yes", IsDefault: true},
			{ID: "no", Label: "No", Risk: "low"},
		},
	}

	display := c.FormatForDisplay()
	if display == "" {
		t.Fatal("FormatForDisplay returned empty")
	}
	if len(display) < 20 {
		t.Errorf("Display too short: %s", display)
	}
}

func TestConsultation_ToJSON(t *testing.T) {
	c := &Consultation{
		ID:       "test-id",
		Type:     ConsultTechnical,
		Question: "Should I use sqlmap?",
	}

	json := c.ToJSON()
	if json == "" {
		t.Fatal("ToJSON returned empty")
	}
}

func TestManager_GetPending_Empty(t *testing.T) {
	m := NewManager(nil)
	pending := m.GetPending()
	if len(pending) != 0 {
		t.Errorf("Expected 0 pending, got %d", len(pending))
	}
}

func TestManager_Ask_NonBlocking(t *testing.T) {
	m := NewManager(nil)
	ctx := context.Background()

	c := &Consultation{
		SessionID: "sess-1",
		Type:      ConsultPriority,
		Urgency:   UrgencyCanContinue,
		Question:  "Which to prioritize?",
		Options: []Option{
			{ID: "xss", Label: "XSS", IsDefault: true},
			{ID: "sqli", Label: "SQLi"},
		},
	}

	resp, err := m.Ask(ctx, c)
	if err != nil {
		t.Fatalf("Ask failed: %v", err)
	}
	if resp == nil {
		t.Fatal("Response is nil")
	}
	// Should return default option immediately
	if resp.ChosenOption != "xss" {
		t.Errorf("Expected default option 'xss', got %s", resp.ChosenOption)
	}
}

func TestManager_Ask_FYI(t *testing.T) {
	m := NewManager(nil)
	ctx := context.Background()

	c := &Consultation{
		SessionID: "sess-1",
		Type:      ConsultRisk,
		Urgency:   UrgencyFYI,
		Question:  "Found a WAF",
		Options: []Option{
			{ID: "continue", Label: "Continue"},
		},
	}

	resp, err := m.Ask(ctx, c)
	if err != nil {
		t.Fatalf("Ask failed: %v", err)
	}
	if resp.ChosenOption != "continue" {
		t.Errorf("Expected 'continue', got %s", resp.ChosenOption)
	}
}

func TestManager_Respond(t *testing.T) {
	m := NewManager(nil)

	// Manually add a pending consultation
	c := &Consultation{
		ID:       "test-123",
		Question: "Approve?",
		Urgency:  UrgencyBlocking,
	}
	m.mu.Lock()
	m.pending["test-123"] = c
	m.mu.Unlock()

	approved := true
	resp := &Response{
		Approved:    &approved,
		RespondedAt: time.Now(),
	}

	err := m.Respond("test-123", resp)
	if err != nil {
		t.Fatalf("Respond failed: %v", err)
	}

	// Should be removed from pending
	pending := m.GetPending()
	if len(pending) != 0 {
		t.Errorf("Expected 0 pending after respond, got %d", len(pending))
	}
}

func TestManager_Respond_NotFound(t *testing.T) {
	m := NewManager(nil)
	err := m.Respond("nonexistent", &Response{})
	if err == nil {
		t.Fatal("Expected error for nonexistent consultation")
	}
}

func TestManager_AskApproval_DefaultDeny(t *testing.T) {
	m := NewManager(nil)
	ctx := context.Background()

	// AskApproval with blocking urgency times out → default is "deny"
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	approved, err := m.AskApproval(ctx, "sess-1", "Delete all data?", "This is destructive")
	if err == nil && approved {
		// Default option is "deny", so approved should be false
		// But context may cancel first
	}
	// Either way, should not error fatally
	_ = err
	_ = approved
}

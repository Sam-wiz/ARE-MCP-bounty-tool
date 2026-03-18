// Package consultation implements the human-in-the-loop system
package consultation

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// Manager handles human consultations
type Manager struct {
	storage    ConsultationStorage
	pending    map[string]*Consultation
	responses  chan *Response
	mu         sync.RWMutex
}

// ConsultationStorage interface for persistence
type ConsultationStorage interface {
	LogConsultation(ctx context.Context, c *types.Consultation) error
	GetConsultation(ctx context.Context, id string) (*types.Consultation, error)
	UpdateConsultation(ctx context.Context, c *types.Consultation) error
}

// Consultation represents a request for human input
type Consultation struct {
	ID         string                 `json:"id"`
	SessionID  string                 `json:"session_id"`
	Type       ConsultationType       `json:"type"`
	Urgency    Urgency                `json:"urgency"`
	Question   string                 `json:"question"`
	Context    string                 `json:"context"`
	Options    []Option               `json:"options,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	Timeout    time.Duration          `json:"timeout"`
	Response   *Response              `json:"response,omitempty"`
}

// ConsultationType defines the type of consultation
type ConsultationType string

const (
	ConsultScope     ConsultationType = "scope"      // About what's in scope
	ConsultEthics    ConsultationType = "ethics"     // Ethical concerns
	ConsultTechnical ConsultationType = "technical"  // Technical approach
	ConsultPriority  ConsultationType = "priority"   // What to prioritize
	ConsultRisk      ConsultationType = "risk"       // Risk assessment
	ConsultApproval  ConsultationType = "approval"   // Needs explicit approval
)

// Urgency defines how urgent the consultation is
type Urgency string

const (
	UrgencyBlocking    Urgency = "blocking"     // Must answer to continue
	UrgencyCanContinue Urgency = "can_continue" // Can continue with default
	UrgencyFYI         Urgency = "fyi"          // Just informational
)

// Option represents a choice option
type Option struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	IsDefault   bool   `json:"is_default,omitempty"`
	Risk        string `json:"risk,omitempty"` // low, medium, high
}

// Response represents a human response
type Response struct {
	ConsultationID string    `json:"consultation_id"`
	ChosenOption   string    `json:"chosen_option,omitempty"`
	FreeText       string    `json:"free_text,omitempty"`
	Approved       *bool     `json:"approved,omitempty"`
	RespondedAt    time.Time `json:"responded_at"`
}

// NewManager creates a new consultation manager
func NewManager(storage ConsultationStorage) *Manager {
	return &Manager{
		storage:   storage,
		pending:   make(map[string]*Consultation),
		responses: make(chan *Response, 100),
	}
}

// Ask asks for human consultation
func (m *Manager) Ask(ctx context.Context, c *Consultation) (*Response, error) {
	c.ID = uuid.New().String()
	c.CreatedAt = time.Now()
	
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Minute
	}
	
	m.mu.Lock()
	m.pending[c.ID] = c
	m.mu.Unlock()
	
	// Log to storage
	if m.storage != nil {
		m.storage.LogConsultation(ctx, &types.Consultation{
			SessionID: c.SessionID,
			Question:  c.Question,
			Context:   c.Context,
			Urgency:   string(c.Urgency),
			Category:  string(c.Type),
		})
	}
	
	// If not blocking, use default
	if c.Urgency != UrgencyBlocking {
		return m.getDefaultResponse(c), nil
	}
	
	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(c.Timeout):
		return m.getDefaultResponse(c), nil
	case resp := <-m.responses:
		if resp.ConsultationID == c.ID {
			c.Response = resp
			return resp, nil
		}
	}
	
	return m.getDefaultResponse(c), nil
}

// AskScope asks for scope clarification
func (m *Manager) AskScope(ctx context.Context, sessionID, question, context string, options []Option) (*Response, error) {
	return m.Ask(ctx, &Consultation{
		SessionID: sessionID,
		Type:      ConsultScope,
		Urgency:   UrgencyBlocking,
		Question:  question,
		Context:   context,
		Options:   options,
	})
}

// AskApproval asks for explicit approval
func (m *Manager) AskApproval(ctx context.Context, sessionID, question, context string) (bool, error) {
	options := []Option{
		{ID: "approve", Label: "Approve", Description: "Proceed with the operation"},
		{ID: "deny", Label: "Deny", Description: "Do not proceed", IsDefault: true},
	}
	
	resp, err := m.Ask(ctx, &Consultation{
		SessionID: sessionID,
		Type:      ConsultApproval,
		Urgency:   UrgencyBlocking,
		Question:  question,
		Context:   context,
		Options:   options,
	})
	if err != nil {
		return false, err
	}
	
	return resp.ChosenOption == "approve" || (resp.Approved != nil && *resp.Approved), nil
}

// AskPriority asks for priority guidance
func (m *Manager) AskPriority(ctx context.Context, sessionID string, options []Option) (*Response, error) {
	return m.Ask(ctx, &Consultation{
		SessionID: sessionID,
		Type:      ConsultPriority,
		Urgency:   UrgencyCanContinue,
		Question:  "Which vulnerability class should I prioritize?",
		Options:   options,
	})
}

// Respond records a human response
func (m *Manager) Respond(id string, resp *Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	c, ok := m.pending[id]
	if !ok {
		return fmt.Errorf("consultation not found: %s", id)
	}
	
	resp.ConsultationID = id
	resp.RespondedAt = time.Now()
	c.Response = resp
	
	// Send to channel
	select {
	case m.responses <- resp:
	default:
	}
	
	delete(m.pending, id)
	return nil
}

// GetPending returns pending consultations
func (m *Manager) GetPending() []*Consultation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	pending := make([]*Consultation, 0, len(m.pending))
	for _, c := range m.pending {
		pending = append(pending, c)
	}
	return pending
}

// getDefaultResponse returns the default response for a consultation
func (m *Manager) getDefaultResponse(c *Consultation) *Response {
	resp := &Response{
		ConsultationID: c.ID,
		RespondedAt:    time.Now(),
	}
	
	// Find default option
	for _, opt := range c.Options {
		if opt.IsDefault {
			resp.ChosenOption = opt.ID
			break
		}
	}
	
	// If no default, use first option
	if resp.ChosenOption == "" && len(c.Options) > 0 {
		resp.ChosenOption = c.Options[0].ID
	}
	
	return resp
}

// FormatForDisplay formats a consultation for human display
func (c *Consultation) FormatForDisplay() string {
	urgencyEmoji := "ℹ️"
	switch c.Urgency {
	case UrgencyBlocking:
		urgencyEmoji = "🛑"
	case UrgencyCanContinue:
		urgencyEmoji = "⚠️"
	}
	
	result := fmt.Sprintf(`
%s CONSULTATION REQUIRED [%s]

Question: %s

Context: %s

`, urgencyEmoji, c.Type, c.Question, c.Context)
	
	if len(c.Options) > 0 {
		result += "Options:\n"
		for i, opt := range c.Options {
			marker := "  "
			if opt.IsDefault {
				marker = "* "
			}
			result += fmt.Sprintf("%s%d. %s", marker, i+1, opt.Label)
			if opt.Description != "" {
				result += fmt.Sprintf(" - %s", opt.Description)
			}
			if opt.Risk != "" {
				result += fmt.Sprintf(" [Risk: %s]", opt.Risk)
			}
			result += "\n"
		}
	}
	
	return result
}

// ToJSON returns JSON representation
func (c *Consultation) ToJSON() string {
	data, _ := json.MarshalIndent(c, "", "  ")
	return string(data)
}

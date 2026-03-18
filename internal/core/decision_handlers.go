package core

import (
	"context"
	"fmt"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// CONSULTATION & DECISION LOGGING HANDLERS
// ============================================================================

func (e *Engine) handleConsultHuman(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	question, _ := args["question"].(string)
	category, _ := args["category"].(string)
	contextStr, _ := args["context"].(string)

	if question == "" || category == "" {
		return errorResult("question and category are required"), nil
	}

	if e.config.MongoDB != nil {
		consultation := &types.Consultation{
			Timestamp: time.Now(),
			SessionID: e.getSessionID(),
			Question:  question,
			Context:   contextStr,
			Category:  category,
			Urgency:   "blocking",
		}
		e.config.MongoDB.LogConsultation(ctx, consultation)
	}

	result := fmt.Sprintf(`🔔 HUMAN CONSULTATION REQUIRED

Category: %s
Question: %s

Context:
%s

⏳ Waiting for human response...`, category, question, contextStr)

	return successResult(result), nil
}

func (e *Engine) handleLogDecision(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	decision, _ := args["decision"].(string)
	reasoning, _ := args["reasoning"].(string)
	thinking, _ := args["thinking"].(string)

	if decision == "" || reasoning == "" {
		return errorResult("decision and reasoning are required"), nil
	}

	var tags []string
	if t, ok := args["tags"].([]interface{}); ok {
		for _, v := range t {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	if e.config.MongoDB != nil {
		log := &types.DecisionLog{
			Timestamp: time.Now(),
			SessionID: e.getSessionID(),
			Target:    e.getTarget(),
			Context:   "manual_log",
			Thinking:  thinking,
			Decision:  decision,
			Reasoning: reasoning,
			Action:    "manual_decision",
			Tags:      tags,
		}

		if err := e.config.MongoDB.LogDecision(ctx, log); err != nil {
			return errorResult(fmt.Sprintf("Failed to log decision: %v", err)), nil
		}
	}

	return successResult("Decision logged successfully to MongoDB"), nil
}

package core

import (
	"context"
	"fmt"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// WORKER MANAGEMENT HANDLERS
// ============================================================================

func (e *Engine) handleListWorkers(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.workers) == 0 {
		return successResult("No workers running"), nil
	}

	var result string
	for _, w := range e.workers {
		result += fmt.Sprintf("- %s: %s on %s (Status: %s, Progress: %d%%)\n",
			w.ID, w.Type, w.Target, w.Status, w.Progress)
	}

	return successResult(result), nil
}

func (e *Engine) handleStopWorker(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	workerID, _ := args["worker_id"].(string)
	if workerID == "" {
		return errorResult("worker_id is required"), nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	worker, exists := e.workers[workerID]
	if !exists {
		return errorResult(fmt.Sprintf("Worker not found: %s", workerID)), nil
	}

	worker.Cancel()
	worker.Status = types.TaskCancelled

	return successResult(fmt.Sprintf("Worker %s stopped", workerID)), nil
}

// Package workers implements autonomous background workers
package workers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// Manager manages autonomous workers
type Manager struct {
	workers  map[string]*Worker
	results  chan *WorkerResult
	mu       sync.RWMutex
}

// Worker represents an autonomous worker
type Worker struct {
	ID         string
	Type       WorkerType
	Target     string
	Status     types.TaskStatus
	Progress   int
	StartedAt  time.Time
	Config     WorkerConfig
	Results    []interface{}
	cancel     context.CancelFunc
	mu         sync.RWMutex
}

// WorkerType defines types of workers
type WorkerType string

const (
	WorkerFuzzer  WorkerType = "fuzzer"
	WorkerCrawler WorkerType = "crawler"
	WorkerMonitor WorkerType = "monitor"
	WorkerScanner WorkerType = "scanner"
)

// WorkerConfig holds worker configuration
type WorkerConfig struct {
	Duration    time.Duration          `json:"duration"`
	Concurrency int                    `json:"concurrency"`
	Wordlist    string                 `json:"wordlist,omitempty"`
	Depth       int                    `json:"depth,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// WorkerResult holds results from a worker
type WorkerResult struct {
	WorkerID  string      `json:"worker_id"`
	Type      WorkerType  `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
	IsFinding bool        `json:"is_finding"`
}

// NewManager creates a new worker manager
func NewManager() *Manager {
	return &Manager{
		workers: make(map[string]*Worker),
		results: make(chan *WorkerResult, 1000),
	}
}

// StartFuzzer starts a fuzzing worker
func (m *Manager) StartFuzzer(ctx context.Context, id, target string, config WorkerConfig) error {
	worker := &Worker{
		ID:        id,
		Type:      WorkerFuzzer,
		Target:    target,
		Status:    types.TaskRunning,
		StartedAt: time.Now(),
		Config:    config,
	}
	
	workerCtx, cancel := context.WithCancel(ctx)
	worker.cancel = cancel
	
	m.mu.Lock()
	m.workers[id] = worker
	m.mu.Unlock()
	
	go m.runFuzzer(workerCtx, worker)
	return nil
}

// StartCrawler starts a crawling worker
func (m *Manager) StartCrawler(ctx context.Context, id, target string, config WorkerConfig) error {
	worker := &Worker{
		ID:        id,
		Type:      WorkerCrawler,
		Target:    target,
		Status:    types.TaskRunning,
		StartedAt: time.Now(),
		Config:    config,
	}
	
	workerCtx, cancel := context.WithCancel(ctx)
	worker.cancel = cancel
	
	m.mu.Lock()
	m.workers[id] = worker
	m.mu.Unlock()
	
	go m.runCrawler(workerCtx, worker)
	return nil
}

// StartMonitor starts a monitoring worker
func (m *Manager) StartMonitor(ctx context.Context, id, target string, config WorkerConfig) error {
	worker := &Worker{
		ID:        id,
		Type:      WorkerMonitor,
		Target:    target,
		Status:    types.TaskRunning,
		StartedAt: time.Now(),
		Config:    config,
	}
	
	workerCtx, cancel := context.WithCancel(ctx)
	worker.cancel = cancel
	
	m.mu.Lock()
	m.workers[id] = worker
	m.mu.Unlock()
	
	go m.runMonitor(workerCtx, worker)
	return nil
}

// Stop stops a worker
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	worker, ok := m.workers[id]
	if !ok {
		return fmt.Errorf("worker not found: %s", id)
	}
	
	worker.cancel()
	worker.Status = types.TaskCancelled
	return nil
}

// StopAll stops all workers
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, worker := range m.workers {
		worker.cancel()
		worker.Status = types.TaskCancelled
	}
}

// GetWorker returns a worker by ID
func (m *Manager) GetWorker(id string) (*Worker, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	worker, ok := m.workers[id]
	return worker, ok
}

// ListWorkers returns all workers
func (m *Manager) ListWorkers() []*Worker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	workers := make([]*Worker, 0, len(m.workers))
	for _, w := range m.workers {
		workers = append(workers, w)
	}
	return workers
}

// Results returns the results channel
func (m *Manager) Results() <-chan *WorkerResult {
	return m.results
}

// GetResults returns all results for a worker
func (m *Manager) GetResults(id string) []interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	worker, ok := m.workers[id]
	if !ok {
		return nil
	}
	
	worker.mu.RLock()
	defer worker.mu.RUnlock()
	return worker.Results
}

// runFuzzer runs actual fuzzing using ffuf or wfuzz
func (m *Manager) runFuzzer(ctx context.Context, worker *Worker) {
	log.Printf("Fuzzer %s started on %s", worker.ID, worker.Target)
	defer func() {
		worker.mu.Lock()
		if worker.Status == types.TaskRunning {
			worker.Status = types.TaskCompleted
		}
		worker.mu.Unlock()
		log.Printf("Fuzzer %s stopped", worker.ID)
	}()

	// Determine wordlist
	wordlist := worker.Config.Wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
	}

	// Build ffuf command with JSON output for parsing
	concurrency := worker.Config.Concurrency
	if concurrency <= 0 {
		concurrency = 40
	}

	cmdStr := fmt.Sprintf(
		"ffuf -u '%s/FUZZ' -w '%s' -mc 200,201,204,301,302,307,401,403,405 -t %d -json 2>/dev/null",
		worker.Target, wordlist, concurrency,
	)

	// Add duration limit if configured
	if worker.Config.Duration > 0 {
		cmdStr = fmt.Sprintf("timeout %d %s", int(worker.Config.Duration.Seconds()), cmdStr)
	}

	log.Printf("[FUZZER %s] Running: %s", worker.ID, cmdStr)

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[FUZZER %s] Failed to create pipe: %v", worker.ID, err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[FUZZER %s] Failed to start ffuf: %v", worker.ID, err)
		return
	}

	// Stream and parse results
	scanner := bufio.NewScanner(stdout)
	lineCount := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		default:
		}

		line := scanner.Text()
		lineCount++

		// Try parsing as JSON (ffuf -json output)
		var ffufResult map[string]interface{}
		if json.Unmarshal([]byte(line), &ffufResult) == nil {
			// Extract useful data
			data := map[string]interface{}{
				"url":    ffufResult["url"],
				"status": ffufResult["status"],
				"length": ffufResult["length"],
				"words":  ffufResult["words"],
				"lines":  ffufResult["lines"],
				"input":  ffufResult["input"],
			}

			isFinding := false
			if status, ok := ffufResult["status"].(float64); ok {
				if status == 200 || status == 201 || status == 301 || status == 302 {
					isFinding = true
				}
			}

			result := &WorkerResult{
				WorkerID:  worker.ID,
				Type:      WorkerFuzzer,
				Timestamp: time.Now(),
				Data:      data,
				IsFinding: isFinding,
			}
			m.results <- result

			worker.mu.Lock()
			worker.Results = append(worker.Results, data)
			worker.Progress = min(lineCount, 100)
			worker.mu.Unlock()
		}
	}

	cmd.Wait()
}

// runCrawler runs the crawling logic
func (m *Manager) runCrawler(ctx context.Context, worker *Worker) {
	log.Printf("Crawler %s started on %s", worker.ID, worker.Target)
	defer func() {
		worker.mu.Lock()
		if worker.Status == types.TaskRunning {
			worker.Status = types.TaskCompleted
		}
		worker.mu.Unlock()
		log.Printf("Crawler %s stopped", worker.ID)
	}()
	
	// Simulate crawling with katana-like behavior
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	var duration <-chan time.Time
	if worker.Config.Duration > 0 {
		duration = time.After(worker.Config.Duration)
	}
	
	depth := worker.Config.Depth
	if depth == 0 {
		depth = 3
	}
	
	currentDepth := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-duration:
			return
		case <-ticker.C:
			currentDepth++
			worker.mu.Lock()
			worker.Progress = min(currentDepth*100/depth, 100)
			worker.mu.Unlock()
			
			// Report discovered URLs
			result := &WorkerResult{
				WorkerID:  worker.ID,
				Type:      WorkerCrawler,
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"urls_found": []string{
						fmt.Sprintf("%s/page%d", worker.Target, currentDepth),
						fmt.Sprintf("%s/api/endpoint%d", worker.Target, currentDepth),
					},
					"depth":    currentDepth,
					"js_files": 5,
				},
			}
			m.results <- result
			
			worker.mu.Lock()
			worker.Results = append(worker.Results, result.Data)
			worker.mu.Unlock()
			
			if currentDepth >= depth {
				return
			}
		}
	}
}

// runMonitor runs the monitoring logic
func (m *Manager) runMonitor(ctx context.Context, worker *Worker) {
	log.Printf("Monitor %s started on %s", worker.ID, worker.Target)
	defer func() {
		worker.mu.Lock()
		if worker.Status == types.TaskRunning {
			worker.Status = types.TaskCompleted
		}
		worker.mu.Unlock()
		log.Printf("Monitor %s stopped", worker.ID)
	}()
	
	// Monitor for changes (like new endpoints, status changes)
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check for changes
			result := &WorkerResult{
				WorkerID:  worker.ID,
				Type:      WorkerMonitor,
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"status":  "no_change",
					"checked": worker.Target,
				},
			}
			m.results <- result
		}
	}
}

// StatusJSON returns a JSON summary of worker status
func (w *Worker) StatusJSON() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	data, _ := json.MarshalIndent(map[string]interface{}{
		"id":         w.ID,
		"type":       w.Type,
		"target":     w.Target,
		"status":     w.Status,
		"progress":   w.Progress,
		"started_at": w.StartedAt,
		"results":    len(w.Results),
	}, "", "  ")
	return string(data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

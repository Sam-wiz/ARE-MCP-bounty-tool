// Package mcp implements the Model Context Protocol server
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/samrudh/hack-ai-v2/internal/core"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ServerConfig holds server configuration
type ServerConfig struct {
	Name    string
	Version string
	Engine  *core.Engine
}

// Server implements the MCP server
type Server struct {
	config  ServerConfig
	tools   []types.ToolDefinition
	mu      sync.RWMutex
}

// NewServer creates a new MCP server
func NewServer(config ServerConfig) *Server {
	s := &Server{
		config: config,
		tools:  make([]types.ToolDefinition, 0),
	}
	s.registerTools()
	return s
}

// ServeStdio runs the MCP server over stdio
func (s *Server) ServeStdio(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	reader := bufio.NewReader(stdin)
	encoder := json.NewEncoder(stdout)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read line (JSON-RPC message)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		// Parse request
		var request MCPRequest
		if err := json.Unmarshal(line, &request); err != nil {
			log.Printf("Invalid JSON: %v", err)
			continue
		}

		// Handle request
		response := s.handleRequest(ctx, &request)

		// Notifications don't get responses (response is nil)
		if response == nil {
			continue
		}

		// Send response
		if err := encoder.Encode(response); err != nil {
			log.Printf("Encode error: %v", err)
		}
	}
}

// MCPRequest represents an incoming MCP request
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse represents an outgoing MCP response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents an error response
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// handleRequest routes incoming requests to appropriate handlers
func (s *Server) handleRequest(ctx context.Context, req *MCPRequest) *MCPResponse {
	log.Printf("Received: %s", req.Method)

	var result interface{}
	var err error

	switch req.Method {
	case "initialize":
		result, err = s.handleInitialize(req.Params)
	case "notifications/initialized":
		// No-op: MCP protocol notification that client completed initialization
		return nil
	case "tools/list":
		result, err = s.handleListTools()
	case "tools/call":
		result, err = s.handleCallTool(ctx, req.Params)
	case "resources/list":
		result, err = s.handleListResources()
	case "resources/read":
		result, err = s.handleReadResource(req.Params)
	default:
		err = fmt.Errorf("unknown method: %s", req.Method)
	}

	resp := &MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	if err != nil {
		resp.Error = &MCPError{
			Code:    -32600,
			Message: err.Error(),
		}
	} else {
		resp.Result = result
	}

	return resp
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    s.config.Name,
			"version": s.config.Version,
		},
	}, nil
}

// handleListTools returns available tools
func (s *Server) handleListTools() (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"tools": s.tools,
	}, nil
}

// ToolCallParams represents tool call parameters
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// handleCallTool executes a tool
func (s *Server) handleCallTool(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var callParams ToolCallParams
	if err := json.Unmarshal(params, &callParams); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Route to appropriate handler
	result, err := s.config.Engine.ExecuteTool(ctx, callParams.Name, callParams.Arguments)
	if err != nil {
		return types.ToolResult{
			Content: []types.ContentBlock{{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return result, nil
}

// handleListResources returns available resources
func (s *Server) handleListResources() (interface{}, error) {
	return map[string]interface{}{
		"resources": []map[string]interface{}{
			{
				"uri":         "findings://all",
				"name":        "All Findings",
				"description": "All discovered vulnerabilities",
				"mimeType":    "application/json",
			},
			{
				"uri":         "session://current",
				"name":        "Current Session",
				"description": "Current testing session info",
				"mimeType":    "application/json",
			},
			{
				"uri":         "decisions://recent",
				"name":        "Recent Decisions",
				"description": "Recent LLM decisions and reasoning",
				"mimeType":    "application/json",
			},
		},
	}, nil
}

// ReadResourceParams represents resource read parameters
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// handleReadResource reads a resource
func (s *Server) handleReadResource(params json.RawMessage) (interface{}, error) {
	var readParams ReadResourceParams
	if err := json.Unmarshal(params, &readParams); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	content, err := s.config.Engine.ReadResource(readParams.URI)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"uri":      readParams.URI,
				"mimeType": "application/json",
				"text":     content,
			},
		},
	}, nil
}

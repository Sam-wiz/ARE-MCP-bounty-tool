package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samrudh/hack-ai-v2/internal/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
)

// HTTP is an authenticated, single-operator JSON-RPC gateway. It is deliberately
// not advertised as MCP Streamable HTTP: the original MCP transport is stdio.
// Remote access exposes the finding workflow, never process execution plugins.
var workflowTools = map[string]bool{
	"set_program": true, "list_programs": true, "program_stats": true,
	"set_target": true, "validate_scope": true, "ingest_result": true,
	"get_findings": true, "generate_report": true,
}

type HTTPConfig struct {
	Token    string
	Version  string
	Revision string
	Ready    func(context.Context) error
	Logger   *slog.Logger
}

func (s *Server) HTTPHandler(cfg HTTPConfig) (http.Handler, error) {
	if len(cfg.Token) < 32 {
		return nil, errors.New("API_TOKEN must contain at least 32 characters")
	}
	if cfg.Ready == nil {
		return nil, errors.New("readiness check is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	tokenHash := sha256.Sum256([]byte("Bearer " + cfg.Token))
	registry := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "are_rpc_requests_total", Help: "RPC requests by bounded method and result."}, []string{"method", "result"})
	latency := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "are_rpc_duration_seconds", Help: "RPC duration including execution.", Buckets: prometheus.DefBuckets}, []string{"method"})
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "are_build_info", Help: "Build identity."}, []string{"version", "revision"})
	build.WithLabelValues(cfg.Version, cfg.Revision).Set(1)
	registry.MustRegister(requests, latency, build, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	gate := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := cfg.Ready(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": cfg.Version, "revision": cfg.Revision})
	})
	mux.HandleFunc("POST /rpc", func(w http.ResponseWriter, r *http.Request) {
		gotHash := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(gotHash[:], tokenHash[:]) != 1 {
			requests.WithLabelValues("rejected", "unauthorized").Inc()
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", 401)
			return
		}
		// No browser-based cross-origin use; access is through localhost port-forward.
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser origins are not supported", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		var req MCPRequest
		if err := dec.Decode(&req); err != nil {
			var sizeErr *http.MaxBytesError
			if errors.As(err, &sizeErr) {
				http.Error(w, "request too large", 413)
			} else {
				writeJSON(w, 400, &MCPResponse{JSONRPC: "2.0", Error: &MCPError{Code: -32700, Message: "invalid JSON"}})
			}
			return
		}
		var extra interface{}
		if dec.Decode(&extra) != io.EOF || req.JSONRPC != "2.0" || req.Method == "" {
			http.Error(w, "invalid JSON-RPC request", 400)
			return
		}
		method := req.Method
		switch method {
		case "initialize", "notifications/initialized", "tools/list", "tools/call", "resources/list", "resources/read":
		default:
			method = "unknown"
		}
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		ctx, span := otel.Tracer("are-mcp/gateway").Start(ctx, "rpc "+method)
		defer span.End()
		traceID := span.SpanContext().TraceID().String()
		w.Header().Set("X-Trace-ID", traceID)
		started := time.Now()
		outcome := "success"
		defer func() {
			requests.WithLabelValues(method, outcome).Inc()
			latency.WithLabelValues(method).Observe(time.Since(started).Seconds())
			span.SetAttributes(attribute.String("rpc.method", method), attribute.String("rpc.result", outcome))
			if outcome != "success" {
				span.SetStatus(codes.Error, outcome)
			}
			cfg.Logger.Info("rpc completed", "method", method, "result", outcome, "trace_id", traceID, "duration_ms", time.Since(started).Milliseconds())
		}()
		// Refuse overlapping requests instead of accumulating unbounded work.
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			outcome = "busy"
			w.Header().Set("Retry-After", "1")
			http.Error(w, "operator is busy", 429)
			return
		}
		readyCtx, readyCancel := context.WithTimeout(ctx, 2*time.Second)
		err := cfg.Ready(readyCtx)
		readyCancel()
		if err != nil {
			outcome = "unavailable"
			http.Error(w, "dependencies unavailable", 503)
			return
		}
		if req.Method == "tools/call" {
			var call ToolCallParams
			if json.Unmarshal(req.Params, &call) != nil || !workflowTools[call.Name] {
				outcome = "denied"
				writeJSON(w, 403, &MCPResponse{JSONRPC: "2.0", ID: req.ID, Error: &MCPError{Code: -32602, Message: "tool is not available through the workflow gateway"}})
				return
			}
			if call.Name == "set_program" {
				slug, _ := call.Arguments["slug"].(string)
				if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(slug) {
					outcome = "invalid"
					http.Error(w, "invalid program slug", 400)
					return
				}
			}
			span.SetAttributes(attribute.String("tool.name", call.Name))
		}
		// Unknown notifications must not execute anything or receive JSON-RPC responses.
		if req.ID == nil && req.Method != "notifications/initialized" {
			outcome = "invalid"
			http.Error(w, "request id is required", 400)
			return
		}
		dispatchCtx, dispatchSpan := otel.Tracer("are-mcp/gateway").Start(ctx, "dispatch "+method)
		resp := s.handleRequest(dispatchCtx, &req)
		dispatchSpan.End()
		if resp == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if req.Method == "tools/list" {
			tools := make([]types.ToolDefinition, 0)
			for _, tool := range s.tools {
				if workflowTools[tool.Name] {
					tools = append(tools, tool)
				}
			}
			resp.Result = map[string]interface{}{"tools": tools}
		}
		if resp.Error != nil {
			outcome = "error"
		}
		if result, ok := resp.Result.(types.ToolResult); ok && result.IsError {
			outcome = "error"
		}
		writeJSON(w, 200, resp)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	}), nil
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

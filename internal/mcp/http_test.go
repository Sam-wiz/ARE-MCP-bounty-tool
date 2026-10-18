package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/core"
)

const testToken = "local-test-token-at-least-32-characters"

func testGateway(t *testing.T, ready func(context.Context) error) http.Handler {
	t.Helper()
	cfg := config.LoadOrDefault("")
	cfg.Workspace.BaseDir = t.TempDir()
	server := NewServer(ServerConfig{Name: "test", Version: "test", Engine: core.NewEngine(core.EngineConfig{Config: cfg})})
	h, err := server.HTTPHandler(HTTPConfig{Token: testToken, Version: "test", Revision: "test-revision", Ready: ready, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func call(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestGatewaySecurityAndValidation(t *testing.T) {
	h := testGateway(t, func(context.Context) error { return nil })
	for _, tc := range []struct {
		name, body, token string
		status            int
	}{
		{"missing token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "", 401},
		{"wrong token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "wrong", 401},
		{"malformed JSON", `{`, testToken, 400},
		{"multiple documents", `{} {}`, testToken, 400},
		{"bad protocol", `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, testToken, 400},
		{"denied executor", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_hunting_script"}}`, testToken, 403},
		{"path traversal", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_program","arguments":{"slug":"../outside"}}}`, testToken, 400},
		{"oversized body", `{"padding":"` + strings.Repeat("a", 1<<20) + `"}`, testToken, 413},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, testToken, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := call(h, "POST", "/rpc", tc.body, tc.token)
			if w.Code != tc.status {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
		})
	}
	r := httptest.NewRequest("POST", "/rpc", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestGatewayReadinessRecovery(t *testing.T) {
	var down atomic.Bool
	h := testGateway(t, func(context.Context) error {
		if down.Load() {
			return errors.New("secret connection details")
		}
		return nil
	})
	for _, state := range []bool{false, true, false} {
		down.Store(state)
		if w := call(h, "GET", "/healthz", "", ""); w.Code != 200 {
			t.Fatal("dependency failure must not fail liveness")
		}
		want := 200
		if state {
			want = 503
		}
		w := call(h, "GET", "/readyz", "", "")
		if w.Code != want || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("readiness: %s", w.Body.String())
		}
		w = call(h, "POST", "/rpc", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, testToken)
		if w.Code != want {
			t.Fatalf("RPC readiness: %d", w.Code)
		}
	}
}
func TestGatewayWorkflowAndMetrics(t *testing.T) {
	h := testGateway(t, func(context.Context) error { return nil })
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_target","arguments":{"domain":"example.test"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ingest_result","arguments":{"title":"Synthetic finding","severity":"info"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_findings","arguments":{}}}`,
	} {
		w := call(h, "POST", "/rpc", body, testToken)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var v struct {
			Result struct {
				IsError bool `json:"isError"`
			}
			Error interface{}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.Result.IsError || v.Error != nil {
			t.Fatal(w.Body.String())
		}
	}
	w := call(h, "GET", "/metrics", "", "")
	if !strings.Contains(w.Body.String(), `are_rpc_requests_total{method="tools/call",result="success"} 3`) {
		t.Fatal(w.Body.String())
	}
	w = call(h, "POST", "/rpc", `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`, testToken)
	if strings.Contains(w.Body.String(), `"execute_hunting_script"`) || !strings.Contains(w.Body.String(), `"ingest_result"`) {
		t.Fatal(w.Body.String())
	}
}
func TestGatewaySerializesOperator(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h := testGateway(t, func(context.Context) error { close(entered); <-release; return nil })
	done := make(chan struct{})
	go func() {
		defer close(done)
		call(h, "POST", "/rpc", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, testToken)
	}()
	<-entered
	w := call(h, "POST", "/rpc", `{"jsonrpc":"2.0","id":2,"method":"initialize"}`, testToken)
	close(release)
	<-done
	if w.Code != 429 {
		t.Fatalf("concurrent request got %d", w.Code)
	}
}

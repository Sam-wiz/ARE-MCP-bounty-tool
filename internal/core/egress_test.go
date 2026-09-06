package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewHTTPClient_RoutesThroughProxy proves that EGRESS_PROXY actually
// causes request-tool traffic to leave through the proxy (the fix for
// geo-blocked targets).
func TestNewHTTPClient_RoutesThroughProxy(t *testing.T) {
	var hits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1) // any request here means we went through the proxy
		w.WriteHeader(200)
		w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()

	os.Setenv("EGRESS_PROXY", proxy.URL)
	defer os.Unsetenv("EGRESS_PROXY")

	e := &Engine{}
	if got := e.egressProxy(); got != proxy.URL {
		t.Fatalf("egressProxy() = %q, want %q", got, proxy.URL)
	}

	client := e.newHTTPClient(5 * time.Second)
	resp, err := client.Get("http://target.example.com/api/me")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected request to route through proxy exactly once, got %d hits", hits)
	}
}

// TestNewHTTPClient_DirectWhenUnset confirms no proxy is used by default.
func TestNewHTTPClient_DirectWhenUnset(t *testing.T) {
	os.Unsetenv("EGRESS_PROXY")
	e := &Engine{}
	if got := e.egressProxy(); got != "" {
		t.Fatalf("egressProxy() = %q, want empty (direct)", got)
	}
	if e.egressLabel() != "DIRECT (no proxy — real IP)" {
		t.Fatalf("egressLabel() = %q", e.egressLabel())
	}
}

// TestRuntimeProxyOverridesEnv confirms opsec_setup's runtime proxy wins.
func TestRuntimeProxyOverridesEnv(t *testing.T) {
	os.Setenv("EGRESS_PROXY", "http://env-proxy:8080")
	defer os.Unsetenv("EGRESS_PROXY")
	e := &Engine{}
	e.setEgressProxy("socks5://runtime-proxy:1080")
	if got := e.egressProxy(); got != "socks5://runtime-proxy:1080" {
		t.Fatalf("runtime override failed: got %q", got)
	}
}

// TestRedactProxy hides credentials for display.
func TestRedactProxy(t *testing.T) {
	if got := redactProxy("socks5://user:secret@1.2.3.4:1080"); got != "socks5://user:***@1.2.3.4:1080" {
		t.Fatalf("redactProxy leaked creds: %q", got)
	}
}

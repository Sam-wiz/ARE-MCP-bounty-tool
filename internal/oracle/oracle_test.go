package oracle

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// testEnv wires an oracle Env to real HTTP (no-redirect) plus an in-memory
// identity map — the same contract the engine provides, minus scope/proxy.
func testEnv(ids map[string]Credential) Env {
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return Env{
		Identity: func(label string) (Credential, bool) { c, ok := ids[label]; return c, ok },
		Run: func(ctx context.Context, r types.ReplayRequest) (HTTPResp, error) {
			var body io.Reader
			if r.Body != "" {
				body = strings.NewReader(r.Body)
			}
			req, err := http.NewRequestWithContext(ctx, orGet(r.Method), r.URL, body)
			if err != nil {
				return HTTPResp{}, err
			}
			for k, v := range r.Headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				return HTTPResp{}, err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return HTTPResp{Status: resp.StatusCode, Headers: resp.Header, Body: string(b)}, nil
		},
	}
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

func TestCORS_PassAndControlBlocks(t *testing.T) {
	// leakyCredentialedCORS: reflects any Origin with credentials AND returns
	// sensitive data — but only to authenticated callers.
	leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		io.WriteString(w, `{"email":"victim@corp.com","ssn":"123-45-6789"}`)
	}))
	defer leaky.Close()

	env := testEnv(map[string]Credential{
		"victim": {Label: "victim", Headers: map[string]string{"Authorization": "Bearer victim-session"}},
	})
	spec := types.ReplaySpec{
		Class:  "cors",
		Marker: "attacker.evil.example",
		Expect: types.ExpectSpec{LeakFields: []string{"victim@corp.com", "123-45-6789"}},
		Requests: []types.ReplayRequest{
			{Role: "exploit", As: "victim", Method: "GET", URL: leaky.URL + "/me", Headers: map[string]string{"Origin": "https://{{marker}}"}},
		},
	}
	res := CORS{}.Verify(context.Background(), spec, env)
	if !res.Passed {
		t.Fatalf("expected PASS, got fail: %s", res.Evidence)
	}
	if !res.Exploit.Observed || res.Control.Observed {
		t.Fatalf("bad signals: exploit=%v control=%v", res.Exploit.Observed, res.Control.Observed)
	}

	// Public variant: data returned WITHOUT auth → control fires → must NOT pass.
	pub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		io.WriteString(w, `{"email":"victim@corp.com","ssn":"123-45-6789"}`)
	}))
	defer pub.Close()
	spec.Requests[0].URL = pub.URL + "/me"
	res = CORS{}.Verify(context.Background(), spec, env)
	if res.Passed {
		t.Fatalf("expected FAIL (public data, control should fire), got pass: %s", res.Evidence)
	}
	if !res.Control.Observed {
		t.Fatalf("expected control to observe public data leak")
	}
}

func TestCORS_RequiresLeakFields(t *testing.T) {
	res := CORS{}.Verify(context.Background(), types.ReplaySpec{Class: "cors",
		Requests: []types.ReplayRequest{{Role: "exploit", URL: "http://x"}}}, testEnv(nil))
	if res.Passed || res.Err == "" {
		t.Fatalf("expected spec error for missing leak_fields, got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// IDOR
// ---------------------------------------------------------------------------

func TestIDOR_PassAndPublicDataBlocks(t *testing.T) {
	// Any authenticated user can read any user's record (cross-tenant IDOR),
	// but anon is rejected.
	idor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"email":"victim@corp.com","phone":"555-0100"}`)
	}))
	defer idor.Close()

	env := testEnv(map[string]Credential{
		"attacker": {Label: "attacker", Headers: map[string]string{"Authorization": "Bearer attacker-session"}},
	})
	spec := types.ReplaySpec{
		Class:  "idor",
		Expect: types.ExpectSpec{LeakFields: []string{"victim@corp.com"}},
		Requests: []types.ReplayRequest{
			{Role: "exploit", As: "attacker", Method: "GET", URL: idor.URL + "/api/users/victim-id"},
		},
	}
	res := IDOR{}.Verify(context.Background(), spec, env)
	if !res.Passed {
		t.Fatalf("expected PASS, got: %s", res.Evidence)
	}

	// Public endpoint: anon also sees the data → not IDOR → control fires.
	pub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"email":"victim@corp.com","phone":"555-0100"}`)
	}))
	defer pub.Close()
	spec.Requests[0].URL = pub.URL + "/api/users/victim-id"
	res = IDOR{}.Verify(context.Background(), spec, env)
	if res.Passed {
		t.Fatalf("expected FAIL for public data, got pass: %s", res.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Auth bypass
// ---------------------------------------------------------------------------

func TestAuthBypass_PassAndPermissiveServerBlocks(t *testing.T) {
	// /promote is unprotected (the bypass); /secret is properly protected (the
	// control that proves the server CAN enforce auth).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/promote":
			w.WriteHeader(http.StatusOK)
		case "/admin/secret":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	env := testEnv(nil)
	env.AllowMutation = true // this test exercises a mutating (POST) bypass
	spec := types.ReplaySpec{
		Class: "auth_bypass",
		Requests: []types.ReplayRequest{
			{Role: "exploit", Method: "POST", URL: srv.URL + "/admin/promote"},
			{Role: "control", Method: "GET", URL: srv.URL + "/admin/secret"},
		},
	}
	res := AuthBypass{}.Verify(context.Background(), spec, env)
	if !res.Passed {
		t.Fatalf("expected PASS, got: %s", res.Evidence)
	}

	// Permissive server: everything returns 200 → control fires → not a bypass.
	perm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer perm.Close()
	spec.Requests[0].URL = perm.URL + "/admin/promote"
	spec.Requests[1].URL = perm.URL + "/admin/secret"
	res = AuthBypass{}.Verify(context.Background(), spec, env)
	if res.Passed {
		t.Fatalf("expected FAIL for permissive server, got pass: %s", res.Evidence)
	}
}

func TestAuthBypass_RequiresControl(t *testing.T) {
	res := AuthBypass{}.Verify(context.Background(), types.ReplaySpec{Class: "auth_bypass",
		Requests: []types.ReplayRequest{{Role: "exploit", URL: "http://x"}}}, testEnv(nil))
	if res.Passed || res.Err == "" {
		t.Fatalf("expected error demanding a control request, got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Blast-radius guard
// ---------------------------------------------------------------------------

func TestBlastRadiusGuard_BlocksMutationByDefault(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := types.ReplaySpec{
		Class: "auth_bypass",
		Requests: []types.ReplayRequest{
			{Role: "exploit", Method: "POST", URL: srv.URL + "/admin/promote"},
			{Role: "control", Method: "GET", URL: srv.URL + "/admin/secret"},
		},
	}
	// Default env: mutation NOT allowed → the POST must be refused, server untouched.
	res := AuthBypass{}.Verify(context.Background(), spec, testEnv(nil))
	if res.Passed {
		t.Fatalf("mutation should be blocked by default")
	}
	if !strings.Contains(res.Err, "blast-radius") {
		t.Fatalf("expected blast-radius error, got %q", res.Err)
	}
	if hit {
		t.Fatalf("server was mutated despite the guard — the POST reached it")
	}

	// Opt in: same replay with AllowMutation=true executes the POST.
	env := testEnv(nil)
	env.AllowMutation = true
	res = AuthBypass{}.Verify(context.Background(), spec, env)
	if !hit {
		t.Fatalf("with allow_mutation the POST should have been sent")
	}
	_ = res
}

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------

func TestOpenRedirect_Pass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := types.ReplaySpec{
		Class:  "open_redirect",
		Marker: "attacker.evil.example",
		Requests: []types.ReplayRequest{
			{Role: "exploit", Method: "GET", URL: srv.URL + "/out?next=https://{{marker}}/"},
		},
	}
	res := OpenRedirect{}.Verify(context.Background(), spec, testEnv(nil))
	if !res.Passed {
		t.Fatalf("expected PASS, got: %s", res.Evidence)
	}

	// Non-redirecting endpoint → no external Location → fail.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer safe.Close()
	spec.Requests[0].URL = safe.URL + "/out?next=https://{{marker}}/"
	res = OpenRedirect{}.Verify(context.Background(), spec, testEnv(nil))
	if res.Passed {
		t.Fatalf("expected FAIL for non-redirecting endpoint, got pass")
	}
}

// ---------------------------------------------------------------------------
// SSRF (uses the real self-hosted OOB catcher)
// ---------------------------------------------------------------------------

func TestSSRF_PassViaOOBCallback(t *testing.T) {
	oob, err := NewHTTPCallbackOOB("127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("start OOB: %v", err)
	}
	defer oob.Close()

	// Vulnerable target: fetches whatever URL is handed to it (server-side).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("u"); u != "" {
			if resp, e := http.Get(u); e == nil {
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	env := testEnv(nil)
	env.OOB = oob
	spec := types.ReplaySpec{
		Class:  "ssrf",
		Expect: types.ExpectSpec{WithinSecs: 5},
		Requests: []types.ReplayRequest{
			{Role: "exploit", Method: "GET", URL: target.URL + "/fetch?u={{marker}}"},
		},
	}
	res := SSRF{}.Verify(context.Background(), spec, env)
	if !res.Passed {
		t.Fatalf("expected PASS via OOB callback, got: %s", res.Evidence)
	}

	// Non-SSRF target: ignores the URL → no callback → fail.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer safe.Close()
	spec.Requests[0].URL = safe.URL + "/fetch?u={{marker}}"
	spec.Expect.WithinSecs = 2
	res = SSRF{}.Verify(context.Background(), spec, env)
	if res.Passed {
		t.Fatalf("expected FAIL (no SSRF, no callback), got pass")
	}
}

func TestSSRF_NoOOBConfigured(t *testing.T) {
	res := SSRF{}.Verify(context.Background(), types.ReplaySpec{Class: "ssrf",
		Requests: []types.ReplayRequest{{Role: "exploit", URL: "http://x"}}}, testEnv(nil))
	if res.Passed || res.Err == "" {
		t.Fatalf("expected error when no OOB client configured, got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Registry / unoracled
// ---------------------------------------------------------------------------

func TestRegistry_UnoracledClass(t *testing.T) {
	res := DefaultRegistry().Verify(context.Background(),
		types.ReplaySpec{Class: "xss", Requests: []types.ReplayRequest{{Role: "exploit", URL: "http://x"}}},
		testEnv(nil))
	if res.Passed {
		t.Fatalf("unoracled class must not pass")
	}
	if !res.Unoracled {
		t.Fatalf("expected Unoracled=true for class xss, got %+v", res)
	}
}

func TestRegistry_ClassAliases(t *testing.T) {
	for _, c := range []string{"auth-bypass", "AUTH_BYPASS", "open-redirect"} {
		if _, ok := DefaultRegistry().Get(c); !ok {
			t.Fatalf("expected alias %q to resolve to an oracle", c)
		}
	}
}

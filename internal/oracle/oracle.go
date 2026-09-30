// Package oracle verifies a bug-bounty finding's impact by EXECUTION, not by
// reading its write-up. Each vuln class has an Oracle that replays the finding
// against the live target (through the engine's scope-enforced, proxied HTTP
// path) and returns a deterministic pass/fail with a captured evidence bundle.
//
// See M1_SUCCESS_ORACLE.md for the design and EVIDENCE_VERIFIER_NOTES.md for why
// text-based verification was abandoned.
package oracle

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// HTTPResp is a captured response from a replayed request. The oracle client
// must NOT follow redirects (so open-redirect / auth flows are visible) and
// should cap the body it reads.
type HTTPResp struct {
	Status  int
	Headers http.Header
	Body    string
}

// Credential is auth material for one identity, applied as request headers
// (e.g. {"Authorization": "Bearer ...", "Cookie": "session=..."}). Secrets are
// resolved at replay time from the engine's secret store — they never live in
// the finding text or in Mongo.
type Credential struct {
	Label   string
	Headers map[string]string
}

// OOBClient issues unique out-of-band tokens and reports callbacks. Used by the
// SSRF oracle: a unique token that later calls back proves the target fetched
// the attacker-controlled URL.
type OOBClient interface {
	NewToken(ctx context.Context) (token, host string, err error)
	Poll(ctx context.Context, token string, within time.Duration) (hit bool, detail string, err error)
}

// Env is the execution environment an oracle runs against. The engine wires Run
// to its scope-enforced, proxied, no-redirect HTTP path; tests wire it to mocks.
type Env struct {
	Run      func(ctx context.Context, r types.ReplayRequest) (HTTPResp, error)
	OOB      OOBClient
	Identity func(label string) (Credential, bool)

	// AllowMutation lifts the blast-radius guard. By default the oracle is
	// READ-ONLY: it refuses mutating verbs (POST/PUT/PATCH/DELETE) so a replay
	// can never alter a real user's data on a live target. The operator opts in
	// per run, and only after ensuring the exploit targets a self-created canary
	// resource — not a real victim's.
	AllowMutation bool
}

// isMutating reports whether a method can change server state. Safe (read-only)
// methods are allowed even under the blast-radius guard.
func isMutating(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

// Oracle verifies impact for one vuln class by executing a replay.
type Oracle interface {
	Class() string
	Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult
}

// Registry maps a vuln class to its oracle.
type Registry struct{ m map[string]Oracle }

// NewRegistry builds a registry from the given oracles.
func NewRegistry(oracles ...Oracle) *Registry {
	r := &Registry{m: map[string]Oracle{}}
	for _, o := range oracles {
		r.m[o.Class()] = o
	}
	return r
}

// DefaultRegistry is the v1 oracle set: the highest-value web/API classes.
func DefaultRegistry() *Registry {
	return NewRegistry(CORS{}, IDOR{}, AuthBypass{}, OpenRedirect{}, SSRF{})
}

// Get returns the oracle for a class (case-insensitive), if one exists.
func (r *Registry) Get(class string) (Oracle, bool) {
	o, ok := r.m[normClass(class)]
	return o, ok
}

// Classes lists the registered classes, sorted.
func (r *Registry) Classes() []string {
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Verify picks the oracle for spec.Class and runs it. If no oracle exists for
// the class it returns an Unoracled result — the honest "the machine cannot
// decide this one; it needs the reviewer/human" outcome, distinct from a fail.
func (r *Registry) Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult {
	class := normClass(spec.Class)
	o, ok := r.Get(class)
	if !ok {
		return types.OracleResult{
			Class:     class,
			Unoracled: true,
			RanAt:     time.Now(),
			Evidence:  fmt.Sprintf("no deterministic oracle for class %q — falls back to reviewer + human judgement", class),
		}
	}
	res := o.Verify(ctx, spec, env)
	if res.Class == "" {
		res.Class = class
	}
	res.RanAt = time.Now()
	return res
}

func normClass(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// tolerate common spellings
	switch s {
	case "auth-bypass", "authbypass", "broken-access-control", "bac":
		return "auth_bypass"
	case "open-redirect", "openredirect":
		return "open_redirect"
	}
	return s
}

// ---------------------------------------------------------------------------
// Shared helpers used by the individual oracles.
// ---------------------------------------------------------------------------

// runReq substitutes the marker, merges the identity's auth headers (request
// headers win), and executes through the Env. Per-request headers may also
// carry {{marker}}.
func runReq(ctx context.Context, env Env, r types.ReplayRequest, marker string) (HTTPResp, error) {
	rr := r
	rr.URL = subst(rr.URL, marker)
	rr.Body = subst(rr.Body, marker)

	merged := map[string]string{}
	if rr.As != "" {
		if env.Identity == nil {
			return HTTPResp{}, fmt.Errorf("request needs identity %q but no identity resolver is configured", rr.As)
		}
		cred, ok := env.Identity(rr.As)
		if !ok {
			return HTTPResp{}, fmt.Errorf("identity %q not configured (set ORACLE_ID_%s)", rr.As, strings.ToUpper(rr.As))
		}
		for k, v := range cred.Headers {
			merged[k] = v
		}
	}
	for k, v := range rr.Headers {
		merged[k] = subst(v, marker)
	}
	rr.Headers = merged
	if strings.TrimSpace(rr.Method) == "" {
		rr.Method = http.MethodGet
	}
	if isMutating(rr.Method) && !env.AllowMutation {
		return HTTPResp{}, fmt.Errorf("blast-radius guard: mutating %s to %s blocked (oracle is read-only by default). Re-run with allow_mutation=true ONLY after confirming this targets a self-created canary resource, not a real user's data", strings.ToUpper(rr.Method), rr.URL)
	}
	if env.Run == nil {
		return HTTPResp{}, fmt.Errorf("no HTTP runner configured in oracle Env")
	}
	return env.Run(ctx, rr)
}

func subst(s, marker string) string {
	if marker == "" {
		return s
	}
	return strings.ReplaceAll(s, "{{marker}}", marker)
}

// pickRole returns the first request with the given role, or nil.
func pickRole(spec types.ReplaySpec, role string) *types.ReplayRequest {
	for i := range spec.Requests {
		if strings.EqualFold(spec.Requests[i].Role, role) {
			return &spec.Requests[i]
		}
	}
	return nil
}

// containsAllFields reports whether body contains every field value (all must
// be present — this is the "victim's private data actually leaked" check).
func containsAllFields(body string, fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(body, f) {
			return false
		}
	}
	return true
}

func statusIn(code int, ok []int) bool {
	if len(ok) == 0 {
		return code >= 200 && code < 300
	}
	for _, c := range ok {
		if c == code {
			return true
		}
	}
	return false
}

// capture builds a compact request+response record for the evidence bundle.
func capture(r types.ReplayRequest, resp HTTPResp) string {
	var b strings.Builder
	as := r.As
	if as == "" {
		as = "anon"
	}
	fmt.Fprintf(&b, "> [%s as %s] %s %s\n", r.Role, as, orGet(r.Method), r.URL)
	fmt.Fprintf(&b, "< %d\n", resp.Status)
	loc := resp.Headers.Get("Location")
	if loc != "" {
		fmt.Fprintf(&b, "< Location: %s\n", loc)
	}
	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	if acao != "" {
		fmt.Fprintf(&b, "< Access-Control-Allow-Origin: %s\n", acao)
		fmt.Fprintf(&b, "< Access-Control-Allow-Credentials: %s\n", resp.Headers.Get("Access-Control-Allow-Credentials"))
	}
	fmt.Fprintf(&b, "< body[:200]: %s\n", clip(resp.Body, 200))
	return b.String()
}

func orGet(m string) string {
	if strings.TrimSpace(m) == "" {
		return "GET"
	}
	return m
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// finalize sets Passed from the asymmetric rule and writes the evidence summary.
func finalize(res types.OracleResult) types.OracleResult {
	res.Passed = res.Err == "" && res.Exploit.Observed && !res.Control.Observed
	var b strings.Builder
	verdict := "FAIL"
	if res.Passed {
		verdict = "PASS"
	}
	if res.Unoracled {
		verdict = "UNORACLED"
	}
	fmt.Fprintf(&b, "[%s] oracle=%s\n", verdict, res.Class)
	if res.Err != "" {
		fmt.Fprintf(&b, "error: %s\n", res.Err)
	}
	fmt.Fprintf(&b, "exploit: observed=%v — %s\n", res.Exploit.Observed, res.Exploit.Detail)
	fmt.Fprintf(&b, "control: observed=%v — %s\n", res.Control.Observed, res.Control.Detail)
	if res.Exploit.Raw != "" {
		fmt.Fprintf(&b, "--- exploit capture ---\n%s", res.Exploit.Raw)
	}
	if res.Control.Raw != "" {
		fmt.Fprintf(&b, "--- control capture ---\n%s", res.Control.Raw)
	}
	res.Evidence = b.String()
	return res
}

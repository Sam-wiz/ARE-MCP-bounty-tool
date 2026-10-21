package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/oracle"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// verify_finding — M1 success oracle. Replays a finding against the live target
// and returns a deterministic pass/fail, instead of judging impact from prose.
//
// A PASS advances the finding to IMPACT_PROVEN and becomes the TRUSTED
// oracle_verified signal the reviewer panel consumes. A FAIL keeps the finding
// alive with the demand "prove the signal". UNORACLED means no deterministic
// oracle exists for the class — it goes to the reviewer/human, never a silent pass.
// ============================================================================

func (e *Engine) handleVerifyFinding(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	// Resolve ORACLE_ID_* identities lazily from .env so credentials added
	// mid-session work without an MCP server restart (BUG-3).
	config.LoadDotEnv()

	// Resolve the replay spec: inline (replay_spec arg) or hydrated from a finding.
	var finding *types.Finding
	findingID := argStr(args, "finding_id")
	if findingID != "" {
		finding = e.lookupFinding(ctx, findingID)
		if finding == nil {
			return errorResult(fmt.Sprintf("❌ finding %q not found in memory or MongoDB", findingID)), nil
		}
	}

	spec, err := replaySpecFromArgs(args, finding)
	if err != nil {
		return errorResult("❌ " + err.Error()), nil
	}
	if strings.TrimSpace(spec.Class) == "" {
		return errorResult("❌ replay spec has no class — set class to one of: " + strings.Join(e.oracles.Classes(), ", ")), nil
	}
	if len(spec.Requests) == 0 {
		return errorResult("❌ replay spec has no requests to execute"), nil
	}

	// Build the execution environment against the engine's real, scope-enforced,
	// proxied HTTP path (mocked in tests).
	env := oracle.Env{
		Run:      e.oracleRunner(),
		Identity: e.resolveIdentity,
		// Read-only by default. Mutating replays require an explicit opt-in
		// (per-call arg or ORACLE_ALLOW_MUTATION=true) so a verification can
		// never alter a real user's data on a live target.
		AllowMutation: argBool(args, "allow_mutation") || strings.EqualFold(os.Getenv("ORACLE_ALLOW_MUTATION"), "true"),
	}

	// SSRF needs an OOB catcher; spin one up on demand and tear it down after.
	if needsOOB(spec.Class) {
		oob, oerr := e.newOOB(ctx)
		if oerr != nil {
			return errorResult("❌ SSRF oracle needs an OOB catcher but it could not start: " + oerr.Error()), nil
		}
		defer oob.Close()
		env.OOB = oob
	}

	res := e.oracles.Verify(ctx, spec, env)

	// Persist the result and (only on PASS) advance the finding's state.
	if finding != nil {
		finding.ReplaySpec = &spec
		finding.ReplayResult = &res
		if res.Passed {
			finding.State = types.FindingImpactProven
		}
		e.mu.Lock()
		e.findings[finding.ID] = finding
		e.mu.Unlock()
		if e.config.MongoDB != nil {
			_ = e.config.MongoDB.SaveFinding(ctx, finding)
			if res.Passed {
				_ = e.config.MongoDB.UpdateFindingState(ctx, finding.ID, types.FindingImpactProven)
			}
		}
	}

	return successResult(formatVerify(res, finding)), nil
}

// oracleRunner returns a Run closure that sends a ReplayRequest through the
// engine's scope-enforced, proxied HTTP client with redirects DISABLED (so the
// open-redirect / auth oracles can see raw 3xx and Location).
func (e *Engine) oracleRunner() func(context.Context, types.ReplayRequest) (oracle.HTTPResp, error) {
	return func(ctx context.Context, r types.ReplayRequest) (oracle.HTTPResp, error) {
		if err := e.validateURLScope(r.URL); err != nil {
			return oracle.HTTPResp{}, err
		}
		client := e.newHTTPClient(20 * time.Second)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		var body io.Reader
		if r.Body != "" {
			body = strings.NewReader(r.Body)
		}
		req, err := http.NewRequestWithContext(ctx, orGet(r.Method), r.URL, body)
		if err != nil {
			return oracle.HTTPResp{}, err
		}
		for k, v := range r.Headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return oracle.HTTPResp{}, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return oracle.HTTPResp{Status: resp.StatusCode, Headers: resp.Header, Body: string(b)}, nil
	}
}

// resolveIdentity looks up an identity's auth material from the environment:
// ORACLE_ID_<LABEL> holds header lines separated by '|' or newlines, e.g.
//
//	ORACLE_ID_ATTACKER='Authorization: Bearer AAA'
//	ORACLE_ID_VICTIM='Cookie: session=BBB'
//
// Secrets stay in the gitignored .env — never in the finding text or Mongo.
func (e *Engine) resolveIdentity(label string) (oracle.Credential, bool) {
	if strings.TrimSpace(label) == "" {
		return oracle.Credential{}, false
	}
	key := "ORACLE_ID_" + strings.ToUpper(strings.NewReplacer("-", "_", " ", "_").Replace(strings.TrimSpace(label)))
	raw := os.Getenv(key)
	if raw == "" {
		return oracle.Credential{}, false
	}
	headers := map[string]string{}
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == '|' || r == '\n' }) {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ':'); i > 0 {
			headers[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	if len(headers) == 0 {
		return oracle.Credential{}, false
	}
	return oracle.Credential{Label: label, Headers: headers}, true
}

// closableOOB is an OOBClient the handler is responsible for shutting down.
type closableOOB interface {
	oracle.OOBClient
	Close() error
}

// newOOB picks the OOB backend for the SSRF oracle:
//   - ORACLE_OOB=interactsh → public/hosted OOB (egress-blind SSRF); needs
//     interactsh-client on PATH.
//   - otherwise (default) → the self-hosted HTTP callback catcher, for targets
//     that can reach the engine's host. Bind/base from ORACLE_OOB_LISTEN /
//     ORACLE_OOB_BASEURL (defaults: ephemeral loopback).
func (e *Engine) newOOB(ctx context.Context) (closableOOB, error) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ORACLE_OOB")), "interactsh") {
		return oracle.NewInteractshOOB(ctx)
	}
	listen := os.Getenv("ORACLE_OOB_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	return oracle.NewHTTPCallbackOOB(listen, os.Getenv("ORACLE_OOB_BASEURL"))
}

func needsOOB(class string) bool {
	c := strings.ToLower(strings.TrimSpace(class))
	return c == "ssrf"
}

// lookupFinding checks the in-memory map first, then MongoDB.
func (e *Engine) lookupFinding(ctx context.Context, id string) *types.Finding {
	e.mu.RLock()
	f := e.findings[id]
	e.mu.RUnlock()
	if f != nil {
		return f
	}
	if e.config.MongoDB != nil {
		if f, err := e.config.MongoDB.GetFinding(ctx, id); err == nil {
			return f
		}
	}
	return nil
}

// replaySpecFromArgs builds the spec from an inline replay_spec object, falling
// back to the finding's stored ReplaySpec.
func replaySpecFromArgs(args map[string]interface{}, finding *types.Finding) (types.ReplaySpec, error) {
	if raw, ok := args["replay_spec"]; ok && raw != nil {
		buf, err := json.Marshal(raw)
		if err != nil {
			return types.ReplaySpec{}, fmt.Errorf("replay_spec is not valid JSON: %v", err)
		}
		var spec types.ReplaySpec
		if err := json.Unmarshal(buf, &spec); err != nil {
			return types.ReplaySpec{}, fmt.Errorf("replay_spec could not be decoded: %v", err)
		}
		return spec, nil
	}
	if finding != nil && finding.ReplaySpec != nil {
		return *finding.ReplaySpec, nil
	}
	return types.ReplaySpec{}, fmt.Errorf("no replay_spec provided and finding has none stored")
}

func orGet(m string) string {
	if strings.TrimSpace(m) == "" {
		return http.MethodGet
	}
	return m
}

func formatVerify(res types.OracleResult, finding *types.Finding) string {
	var b strings.Builder
	emoji := "⛔"
	label := "FAIL — impact NOT reproduced by execution"
	switch {
	case res.Unoracled:
		emoji = "❔"
		label = "UNORACLED — no deterministic oracle for this class; hand to reviewer/human"
	case res.Passed:
		emoji = "✅"
		label = "PASS — impact demonstrated by execution"
	}
	fmt.Fprintf(&b, "%s ORACLE VERDICT: %s\n", emoji, label)
	fmt.Fprintf(&b, "class: %s\n", res.Class)
	if res.Err != "" {
		fmt.Fprintf(&b, "error: %s\n", res.Err)
	}
	fmt.Fprintf(&b, "\nexploit signal: observed=%v — %s\n", res.Exploit.Observed, res.Exploit.Detail)
	fmt.Fprintf(&b, "control signal: observed=%v — %s\n", res.Control.Observed, res.Control.Detail)
	fmt.Fprintf(&b, "\npass rule: exploit.observed && !control.observed = %v\n", res.Passed)

	if finding != nil {
		if res.Passed {
			fmt.Fprintf(&b, "\n→ finding %s advanced to IMPACT_PROVEN. Now run review_report — the panel will TRUST this oracle result and focus on scope/duplication.\n", finding.ID)
		} else if !res.Unoracled {
			fmt.Fprintf(&b, "\n→ finding %s stays put. The replay did not reproduce impact — fix the exploit or drop the claim; do not submit on impact grounds.\n", finding.ID)
		}
	}
	if res.Evidence != "" {
		b.WriteString("\n--- evidence bundle ---\n")
		b.WriteString(res.Evidence)
	}
	return b.String()
}

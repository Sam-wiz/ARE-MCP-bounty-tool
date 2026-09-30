package oracle

import (
	"context"
	"fmt"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// SSRF proves the target fetched an attacker-controlled URL, out-of-band.
//
//	setup:   mint a unique OOB token → host.
//	exploit: inject http://<host> ({{marker}}) into the sink, then poll the OOB
//	         channel → PASS signal: the unique token calls back within the window.
//	control: none needed — the token is unique, so a callback can only come from
//	         the target dereferencing the injected URL (built-in anti-gaming).
//
// Requires an OOB client (Env.OOB). Without one the oracle returns an error
// (NOT a pass and NOT unoracled — the class is oracled, the dependency is just
// missing).
type SSRF struct{}

func (SSRF) Class() string { return "ssrf" }

func (SSRF) Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult {
	res := types.OracleResult{Class: "ssrf"}
	if env.OOB == nil {
		res.Err = "ssrf oracle needs an OOB client (e.g. interactsh / HTTP callback) — none configured; set ORACLE_OOB_LISTEN"
		return finalize(res)
	}
	ex := pickRole(spec, "exploit")
	if ex == nil {
		res.Err = "no 'exploit' request in replay spec (must inject {{marker}} into the SSRF sink)"
		return finalize(res)
	}

	token, host, err := env.OOB.NewToken(ctx)
	if err != nil {
		res.Err = "could not mint OOB token: " + err.Error()
		return finalize(res)
	}

	exResp, rerr := runReq(ctx, env, *ex, host)
	rawStatus := "n/a"
	if rerr == nil {
		rawStatus = fmt.Sprintf("%d", exResp.Status)
	}

	within := 15 * time.Second
	if spec.Expect.WithinSecs > 0 {
		within = time.Duration(spec.Expect.WithinSecs) * time.Second
	}
	hit, detail, perr := env.OOB.Poll(ctx, token, within)

	obsDetail := fmt.Sprintf("injected OOB host=%s, request status=%s, callback=%v", host, rawStatus, hit)
	if perr != nil {
		obsDetail += " (poll error: " + perr.Error() + ")"
	}
	if detail != "" {
		obsDetail += " [" + detail + "]"
	}
	res.Exploit = types.OracleSignal{
		Kind:     "oob_callback",
		Observed: hit,
		Detail:   obsDetail,
		Raw:      capture(*ex, exResp),
	}
	// No negative control for a unique-token OOB signal.
	res.Control = types.OracleSignal{Kind: "oob_callback", Observed: false, Detail: "n/a — unique OOB token is self-authenticating"}
	return finalize(res)
}

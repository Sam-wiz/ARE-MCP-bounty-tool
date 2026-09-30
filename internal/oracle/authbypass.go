package oracle

import (
	"context"
	"fmt"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// AuthBypass proves a protected action can be performed without valid auth.
//
//	exploit: perform the privileged action with NO / stripped / tampered session
//	         → PASS signal: success status (expect.status_ok, default 2xx).
//	control: REQUIRED — an unauthenticated request to an endpoint that SHOULD be
//	         denied (e.g. a sibling protected route). If that control ALSO
//	         succeeds, the server is indiscriminately permissive (or the target
//	         echoes 200 for everything) → not a real bypass.
//
// The control is what makes this deterministic rather than "the endpoint
// returned 200": it proves the server CAN reject unauth, yet served the exploit.
type AuthBypass struct{}

func (AuthBypass) Class() string { return "auth_bypass" }

func (AuthBypass) Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult {
	res := types.OracleResult{Class: "auth_bypass"}
	ex := pickRole(spec, "exploit")
	if ex == nil {
		res.Err = "no 'exploit' request in replay spec (the unauthenticated privileged action)"
		return finalize(res)
	}
	ctrl := pickRole(spec, "control")
	if ctrl == nil {
		res.Err = "auth_bypass oracle requires a 'control' request: an unauth call to a route that SHOULD be denied, proving the server enforces auth elsewhere"
		return finalize(res)
	}

	exResp, err := runReq(ctx, env, *ex, spec.Marker)
	if err != nil {
		res.Err = "exploit request failed: " + err.Error()
		return finalize(res)
	}
	exOK := statusIn(exResp.Status, spec.Expect.StatusOK)
	res.Exploit = types.OracleSignal{
		Kind:     "state_change",
		Observed: exOK,
		Detail:   fmt.Sprintf("unauth privileged action status=%d (success=%v)", exResp.Status, exOK),
		Raw:      capture(*ex, exResp),
	}

	ctrlResp, cerr := runReq(ctx, env, *ctrl, spec.Marker)
	if cerr != nil {
		res.Control = types.OracleSignal{Kind: "state_change", Observed: false, Detail: "control errored: " + cerr.Error()}
	} else {
		ctrlOK := statusIn(ctrlResp.Status, spec.Expect.StatusOK)
		res.Control = types.OracleSignal{
			Kind:     "state_change",
			Observed: ctrlOK,
			Detail:   fmt.Sprintf("should-be-denied control status=%d (unexpected_success=%v)", ctrlResp.Status, ctrlOK),
			Raw:      capture(*ctrl, ctrlResp),
		}
	}
	return finalize(res)
}

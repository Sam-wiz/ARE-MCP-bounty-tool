package oracle

import (
	"context"
	"fmt"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// IDOR proves broken object-level authorization: attacker-A reads victim-B's
// private resource. This is the counterfactual (M2) in its purest form.
//
//	exploit: as attacker, request victim-B's resource id
//	         → PASS signal: B's private fields (expect.leak_fields) appear.
//	control: the SAME resource requested as anon (or an explicit control request)
//	         must NOT return those fields — if it does, the data is public /
//	         unauthenticated (a different, weaker issue), not cross-tenant IDOR.
//
// Requires expect.leak_fields = victim-B's private values (email, token, PII…)
// that the attacker should never see.
type IDOR struct{}

func (IDOR) Class() string { return "idor" }

func (IDOR) Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult {
	res := types.OracleResult{Class: "idor"}
	if len(spec.Expect.LeakFields) == 0 {
		res.Err = "idor oracle requires expect.leak_fields (victim-B's private values the attacker must not see)"
		return finalize(res)
	}
	ex := pickRole(spec, "exploit")
	if ex == nil {
		res.Err = "no 'exploit' request in replay spec (attacker requesting victim's resource)"
		return finalize(res)
	}
	if ex.As == "" {
		res.Err = "idor exploit request must run as an authenticated attacker identity (set 'as')"
		return finalize(res)
	}

	exResp, err := runReq(ctx, env, *ex, spec.Marker)
	if err != nil {
		res.Err = "exploit request failed: " + err.Error()
		return finalize(res)
	}
	leaked := exResp.Status < 400 && containsAllFields(exResp.Body, spec.Expect.LeakFields)
	res.Exploit = types.OracleSignal{
		Kind:     "data_leak",
		Observed: leaked,
		Detail:   fmt.Sprintf("attacker(%s) status=%d victim_fields_present=%v", ex.As, exResp.Status, leaked),
		Raw:      capture(*ex, exResp),
	}

	// Control: anon (or explicit control) hitting the same resource. Observed =
	// victim data returned without the attacker's session → it's public, not IDOR.
	ctrlReq := controlOrAnon(spec, *ex)
	ctrlResp, cerr := runReq(ctx, env, ctrlReq, spec.Marker)
	if cerr != nil {
		res.Control = types.OracleSignal{Kind: "data_leak", Observed: false, Detail: "control errored: " + cerr.Error()}
	} else {
		obs := ctrlResp.Status < 400 && containsAllFields(ctrlResp.Body, spec.Expect.LeakFields)
		res.Control = types.OracleSignal{
			Kind:     "data_leak",
			Observed: obs,
			Detail:   fmt.Sprintf("control(%s) status=%d victim_fields_present=%v", orAnon(ctrlReq.As), ctrlResp.Status, obs),
			Raw:      capture(ctrlReq, ctrlResp),
		}
	}
	return finalize(res)
}

func orAnon(s string) string {
	if s == "" {
		return "anon"
	}
	return s
}

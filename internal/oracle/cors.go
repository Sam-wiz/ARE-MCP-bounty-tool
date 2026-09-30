package oracle

import (
	"context"
	"fmt"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// CORS proves a credentialed cross-origin read of sensitive data — not just a
// reflected header. This is the #1 false-positive class the v1 engine tripped
// on (an ACAO reflection is an indicator, never impact).
//
//	exploit: authenticated read with Origin: https://<marker> (attacker origin)
//	         → PASS signal: ACAO echoes the attacker origin AND ACAC:true AND the
//	           body carries the sensitive fields (expect.leak_fields).
//	control: the SAME read UNauthenticated (anon) must NOT return those fields —
//	         otherwise the data is public and CORS grants nothing.
//
// Requires expect.leak_fields (the sensitive values that prove the read).
type CORS struct{}

func (CORS) Class() string { return "cors" }

func (CORS) Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult {
	res := types.OracleResult{Class: "cors"}
	if len(spec.Expect.LeakFields) == 0 {
		res.Err = "cors oracle requires expect.leak_fields (the sensitive values that must appear in the cross-origin read)"
		return finalize(res)
	}
	ex := pickRole(spec, "exploit")
	if ex == nil {
		res.Err = "no 'exploit' request in replay spec"
		return finalize(res)
	}
	marker := spec.Marker
	if marker == "" {
		marker = "attacker.evil.example"
	}

	// Attacker origin the browser would send. Prefer the request's own Origin
	// header (templated), else synthesize from the marker.
	origin := subst(headerOf(ex.Headers, "Origin"), marker)
	if origin == "" {
		origin = "https://" + marker
		if ex.Headers == nil {
			ex.Headers = map[string]string{}
		}
		ex.Headers["Origin"] = origin
	}

	exResp, err := runReq(ctx, env, *ex, marker)
	if err != nil {
		res.Err = "exploit request failed: " + err.Error()
		return finalize(res)
	}
	acao := exResp.Headers.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(exResp.Headers.Get("Access-Control-Allow-Credentials"), "true")
	// For a *credentialed* read the browser requires ACAO to ECHO the origin;
	// ACAO:* is ignored when credentials are involved, so it does NOT count.
	credentialedReflect := acac && acao == origin
	bodyLeaks := containsAllFields(exResp.Body, spec.Expect.LeakFields)

	res.Exploit = types.OracleSignal{
		Kind:     "data_leak",
		Observed: credentialedReflect && bodyLeaks,
		Detail:   fmt.Sprintf("ACAO=%q ACAC=%v origin=%q sensitive_body=%v", acao, acac, origin, bodyLeaks),
		Raw:      capture(*ex, exResp),
	}

	// Negative control: same read as anon. If the sensitive fields come back
	// unauthenticated, the data is public → CORS impact is void.
	ctrlReq := controlOrAnon(spec, *ex)
	ctrlResp, cerr := runReq(ctx, env, ctrlReq, marker)
	if cerr != nil {
		res.Control = types.OracleSignal{Kind: "data_leak", Observed: false, Detail: "control (anon) errored: " + cerr.Error()}
	} else {
		res.Control = types.OracleSignal{
			Kind:     "data_leak",
			Observed: containsAllFields(ctrlResp.Body, spec.Expect.LeakFields),
			Detail:   fmt.Sprintf("anon read status=%d sensitive_body=%v", ctrlResp.Status, containsAllFields(ctrlResp.Body, spec.Expect.LeakFields)),
			Raw:      capture(ctrlReq, ctrlResp),
		}
	}
	return finalize(res)
}

// headerOf does a case-insensitive lookup in a string-keyed header map.
func headerOf(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// controlOrAnon returns the explicit control request if the spec has one, else
// an anonymous copy of the exploit request.
func controlOrAnon(spec types.ReplaySpec, ex types.ReplayRequest) types.ReplayRequest {
	if c := pickRole(spec, "control"); c != nil {
		return *c
	}
	anon := ex
	anon.Role = "control"
	anon.As = ""
	// drop any auth headers carried inline
	clean := map[string]string{}
	for k, v := range ex.Headers {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") {
			continue
		}
		clean[k] = v
	}
	anon.Headers = clean
	return anon
}

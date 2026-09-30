package oracle

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// OpenRedirect proves a redirect param sends the browser to an attacker host.
//
//	exploit: request with the attacker host ({{marker}} or expect.redirect_to)
//	         in the redirect parameter (client must NOT follow redirects)
//	         → PASS signal: 3xx with a Location whose host is the attacker host.
//	control: OPTIONAL — a benign value should stay on-origin. A unique attacker
//	         host in Location can't be faked, so the control mainly guards
//	         against a target that 3xx-es everywhere.
type OpenRedirect struct{}

func (OpenRedirect) Class() string { return "open_redirect" }

func (OpenRedirect) Verify(ctx context.Context, spec types.ReplaySpec, env Env) types.OracleResult {
	res := types.OracleResult{Class: "open_redirect"}
	ex := pickRole(spec, "exploit")
	if ex == nil {
		res.Err = "no 'exploit' request in replay spec"
		return finalize(res)
	}
	attacker := spec.Expect.RedirectTo
	if attacker == "" {
		attacker = spec.Marker
	}
	if attacker == "" {
		attacker = "attacker.evil.example"
	}

	exResp, err := runReq(ctx, env, *ex, attacker)
	if err != nil {
		res.Err = "exploit request failed: " + err.Error()
		return finalize(res)
	}
	loc := exResp.Headers.Get("Location")
	is3xx := exResp.Status >= 300 && exResp.Status < 400
	toAttacker := locationTargets(loc, attacker)
	res.Exploit = types.OracleSignal{
		Kind:     "redirect",
		Observed: is3xx && toAttacker,
		Detail:   fmt.Sprintf("status=%d Location=%q → attacker(%s)=%v", exResp.Status, loc, attacker, toAttacker),
		Raw:      capture(*ex, exResp),
	}

	if ctrl := pickRole(spec, "control"); ctrl != nil {
		ctrlResp, cerr := runReq(ctx, env, *ctrl, attacker)
		if cerr != nil {
			res.Control = types.OracleSignal{Kind: "redirect", Observed: false, Detail: "control errored: " + cerr.Error()}
		} else {
			cloc := ctrlResp.Headers.Get("Location")
			res.Control = types.OracleSignal{
				Kind:     "redirect",
				Observed: locationTargets(cloc, attacker),
				Detail:   fmt.Sprintf("benign control status=%d Location=%q", ctrlResp.Status, cloc),
				Raw:      capture(*ctrl, ctrlResp),
			}
		}
	} else {
		res.Control = types.OracleSignal{Kind: "redirect", Observed: false, Detail: "no control supplied (unique attacker host makes this low-risk)"}
	}
	return finalize(res)
}

// locationTargets reports whether a Location header points at the attacker host.
// Handles absolute URLs, scheme-relative (//host), and raw host substrings.
func locationTargets(loc, attacker string) bool {
	loc = strings.TrimSpace(loc)
	if loc == "" || attacker == "" {
		return false
	}
	host := attacker
	if u, err := url.Parse(attacker); err == nil && u.Host != "" {
		host = u.Host
	}
	if u, err := url.Parse(loc); err == nil && u.Host != "" {
		return strings.EqualFold(u.Host, host)
	}
	// scheme-relative //attacker/...
	if strings.HasPrefix(loc, "//") {
		rest := strings.TrimPrefix(loc, "//")
		return strings.HasPrefix(strings.ToLower(rest), strings.ToLower(host))
	}
	return false
}

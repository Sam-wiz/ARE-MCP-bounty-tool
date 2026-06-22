// Package precheck is the cheap, deterministic first stage before the expensive
// LLM reviewer panel. It does NOT try to predict whether a triager will accept a
// finding (proven not text-separable) — instead it catches objective
// disqualifiers and known false-positive classes with high precision, enforces
// report completeness, and scores value, so the panel/human effort is spent only
// where it matters.
//
// Design rule: HARD-disqualify only on things that are deterministically certain
// (out-of-scope, own-duplicate). Everything judgment-y (FP-class patterns,
// completeness) is a WARNING that lowers the value score but never hard-blocks a
// potentially-real finding.
package precheck

import (
	"regexp"
	"strings"
)

// Verdict is the precheck outcome.
type Verdict string

const (
	Disqualified Verdict = "DISQUALIFIED" // out-of-scope or own-duplicate — do not spend effort
	Proceed      Verdict = "PROCEED"      // passed; send to panel / human
)

// Result is the precheck outcome for one finding.
type Result struct {
	Verdict      Verdict         `json:"verdict"`
	Reasons      []string        `json:"reasons"`       // why disqualified (hard)
	Warnings     []string        `json:"warnings"`      // FP-class / quality concerns (soft)
	FPClasses    []string        `json:"fp_classes"`    // matched known false-positive classes
	Completeness map[string]bool `json:"completeness"`  // has_repro / has_poc / has_impact
	ValueScore   float64         `json:"value_score"`   // priority: payout * severity * penalties
	SkipPanel    bool            `json:"skip_panel"`    // true when disqualified → don't run the panel
}

// Input describes the finding plus the context needed for deterministic checks.
type Input struct {
	Title       string
	Description string
	PoC         string
	Evidence    string
	VulnType    string
	Severity    string
	Target      string
	URL         string

	InScope     []string // program scope (host or host/path patterns)
	OutOfScope  []string
	PayoutMax   int

	// PriorSubmissions lets precheck flag an own-duplicate (something you already
	// filed). Each is a compact key like "program|vuln_type|target".
	PriorKeys []string
}

// fpRule is a high-precision known-false-positive signature.
type fpRule struct {
	class string
	re    *regexp.Regexp
	note  string
}

var fpRules = []fpRule{
	{"public-client-key", regexp.MustCompile(`(?i)NEXT_PUBLIC_|VITE_|REACT_APP_|\bpk_(live|test)_|publishable[ _-]?key|tokenization[ _-]?key|\bproduction_[a-z0-9]{6,}_`),
		"Contains a public-by-design client key/var (NEXT_PUBLIC_*, Stripe pk_*, Braintree tokenization, etc.). Presence in a bundle is NOT a leak unless privileged use is demonstrated."},
	{"self-xss", regexp.MustCompile(`(?i)self[ _-]?xss`),
		"Self-XSS is routinely closed as informational."},
	{"missing-header-only", regexp.MustCompile(`(?i)missing (security )?header|x-frame-options|x-content-type-options|strict-transport-security|content-security-policy header`),
		"Missing-security-header findings are informational without demonstrated exploitation."},
	{"spec-nitpick-pkce", regexp.MustCompile(`(?i)(RS256|ES256)[^.]{0,40}PKCE|PKCE[^.]{0,40}(RS256|ES256)`),
		"OIDC discovery listing signing algs as PKCE methods is a spec-nitpick, near-always informational."},
	{"clickjacking-nolow", regexp.MustCompile(`(?i)clickjack|frameable|frame-ancestors`),
		"Clickjacking without a demonstrated sensitive-action chain is low/informational."},
	{"verbose-error", regexp.MustCompile(`(?i)verbose error|stack trace disclosure|version disclosure|banner`),
		"Error/version disclosure alone is informational."},
}

var (
	reRepro  = regexp.MustCompile(`(?i)step[s]?\b|reproduc|steps to|\b1[\.\)]\s|curl\s|POST\s|GET\s+/|request:|http/1`)
	rePoC    = regexp.MustCompile(`(?i)proof[ -]?of[ -]?concept|\bpoc\b|payload|exploit|<script|curl\s|response:`)
	reImpact = regexp.MustCompile(`(?i)impact|attacker can|allows an attacker|leads to|results in|unauthorized|exfiltrat|takeover|escalat`)
)

// Check runs the deterministic precheck.
func Check(in Input) Result {
	res := Result{Completeness: map[string]bool{}}
	blob := strings.ToLower(strings.Join([]string{in.Title, in.Description, in.PoC, in.Evidence}, "\n"))

	// 1. Scope — a hard, safe disqualifier. Only enforced when scope is defined.
	if len(in.InScope) > 0 {
		host := targetHost(in.Target, in.URL)
		if host != "" && !inScope(host, in.InScope, in.OutOfScope) {
			res.Reasons = append(res.Reasons, "Out of scope: "+host)
		}
	}

	// 2. Own-duplicate — hard, safe disqualifier.
	key := strings.ToLower(in.VulnType + "|" + targetHost(in.Target, in.URL))
	for _, pk := range in.PriorKeys {
		if strings.Contains(strings.ToLower(pk), key) && key != "|" {
			res.Reasons = append(res.Reasons, "Likely own-duplicate of a prior submission: "+pk)
			break
		}
	}

	// 3. FP-class patterns — WARNINGS (never hard-block; they lower value).
	for _, r := range fpRules {
		if r.re.MatchString(blob) {
			res.FPClasses = append(res.FPClasses, r.class)
			res.Warnings = append(res.Warnings, r.class+": "+r.note)
		}
	}

	// 4. Completeness — WARNINGS.
	res.Completeness["has_repro"] = reRepro.MatchString(blob)
	res.Completeness["has_poc"] = rePoC.MatchString(blob)
	res.Completeness["has_impact"] = reImpact.MatchString(blob)
	for k, ok := range res.Completeness {
		if !ok {
			res.Warnings = append(res.Warnings, "Incomplete: report is missing "+strings.TrimPrefix(k, "has_"))
		}
	}

	// 5. Value score = payout * severity * FP penalty.
	sev := severityWeight(in.Severity)
	payout := float64(in.PayoutMax)
	if payout <= 0 {
		payout = 1
	}
	penalty := 1.0
	if len(res.FPClasses) > 0 {
		penalty = 0.4 // matched a known FP class → deprioritize
	}
	res.ValueScore = payout * sev * penalty

	// Verdict.
	if len(res.Reasons) > 0 {
		res.Verdict = Disqualified
		res.SkipPanel = true
		res.ValueScore = 0 // moot once disqualified
	} else {
		res.Verdict = Proceed
	}
	return res
}

func severityWeight(s string) float64 {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "P1", "CRITICAL":
		return 5
	case "P2", "HIGH":
		return 4
	case "P3", "MEDIUM":
		return 3
	case "P4", "LOW":
		return 2
	case "P5", "INFO", "INFORMATIONAL":
		return 1
	}
	return 2.5 // unknown severity
}

func targetHost(target, url string) string {
	s := strings.TrimSpace(target)
	if s == "" {
		s = url
	}
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/ "); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// inScope mirrors the engine's host/wildcard matching (case-insensitive,
// *.example.com matches subdomains and apex), kept local so precheck has no
// dependency on core.
func inScope(host string, in, out []string) bool {
	matched := false
	for _, p := range in {
		if hostMatch(host, p) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, p := range out {
		if hostMatch(host, p) {
			return false
		}
	}
	return true
}

func hostMatch(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	// reduce a "host/path" scope entry to its host for this coarse check
	if i := strings.Index(pattern, "/"); i != -1 {
		pattern = pattern[:i]
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		apex := pattern[2:]
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
	return false
}

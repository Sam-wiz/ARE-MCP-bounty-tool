package types

import "time"

// ============================================================================
// SUCCESS-ORACLE (M1) — execution-grounded impact verification
//
// The calibration work proved you cannot predict triage from a finding's TEXT
// (~48% ceiling), and that polished write-ups actively fool a text reviewer.
// So instead of grading prose, the engine REPLAYS the finding against the live
// target and a per-vuln-class oracle returns a deterministic pass/fail. That
// result — not the model's paragraph — advances a finding to IMPACT_PROVEN and
// is the TRUSTED signal the reviewer panel consumes.
//
// Pattern precedent: ExploitGym (UC Berkeley) verifies exploits by executing
// them and checking a ground-truth signal. We adopt the pattern (success
// oracle) for the web/API domain, not their binary/kernel benchmark.
// ============================================================================

// ReplaySpec is the machine-readable replay a finding must carry so an oracle
// can verify impact by execution. Requests are templated: "{{marker}}" is
// replaced with a per-run unique token (OOB host / canary), and each request
// runs under the identity named by ReplayRequest.As.
type ReplaySpec struct {
	Class      string          `json:"class" bson:"class"`                               // idor | ssrf | cors | auth_bypass | open_redirect
	Requests   []ReplayRequest `json:"requests" bson:"requests"`                         // ordered; roles: exploit | control | setup
	Identities []string        `json:"identities,omitempty" bson:"identities,omitempty"` // labels this spec needs (attacker, victim, anon)
	Marker     string          `json:"marker,omitempty" bson:"marker,omitempty"`         // unique per-run token; SSRF sets it from OOB
	Expect     ExpectSpec      `json:"expect" bson:"expect"`                             // what proves success
}

// ReplayRequest is one HTTP request in a replay. Body/URL/Headers may contain
// "{{marker}}". As selects the identity to authenticate as ("" = anonymous).
type ReplayRequest struct {
	Role    string            `json:"role" bson:"role"`
	As      string            `json:"as,omitempty" bson:"as,omitempty"`
	Method  string            `json:"method" bson:"method"`
	URL     string            `json:"url" bson:"url"`
	Headers map[string]string `json:"headers,omitempty" bson:"headers,omitempty"`
	Body    string            `json:"body,omitempty" bson:"body,omitempty"`
}

// ExpectSpec describes the signal that proves success for the oracle's class.
type ExpectSpec struct {
	Signal     string   `json:"signal,omitempty" bson:"signal,omitempty"`           // data_leak | oob_callback | state_change | redirect
	LeakFields []string `json:"leak_fields,omitempty" bson:"leak_fields,omitempty"` // sensitive values that must appear (data_leak)
	StatusOK   []int    `json:"status_ok,omitempty" bson:"status_ok,omitempty"`     // acceptable success statuses (state_change)
	RedirectTo string   `json:"redirect_to,omitempty" bson:"redirect_to,omitempty"` // attacker host the Location must point to (redirect)
	WithinSecs int      `json:"within_secs,omitempty" bson:"within_secs,omitempty"` // OOB callback poll window (oob_callback)
}

// OracleSignal is a single machine-checkable observation from a replayed request.
type OracleSignal struct {
	Kind     string `json:"kind" bson:"kind"` // data_leak | oob_callback | state_change | redirect
	Observed bool   `json:"observed" bson:"observed"`
	Detail   string `json:"detail,omitempty" bson:"detail,omitempty"`
	Raw      string `json:"raw,omitempty" bson:"raw,omitempty"` // captured request+response, for the evidence bundle
}

// OracleResult is the deterministic verdict for one finding.
//
// The pass rule is asymmetric and non-negotiable: Passed = Exploit.Observed &&
// !Control.Observed. The negative control is the counterfactual — a finding
// only proves impact when the attacker action fires the signal AND a baseline
// (anon / benign) does not. Unoracled=true is a distinct third value: "no
// deterministic oracle for this class — hand to the reviewer/human", NOT a pass.
type OracleResult struct {
	Class     string       `json:"class" bson:"class"`
	Passed    bool         `json:"passed" bson:"passed"`
	Unoracled bool         `json:"unoracled,omitempty" bson:"unoracled,omitempty"`
	Exploit   OracleSignal `json:"exploit" bson:"exploit"`
	Control   OracleSignal `json:"control" bson:"control"`
	Evidence  string       `json:"evidence,omitempty" bson:"evidence,omitempty"`
	Err       string       `json:"err,omitempty" bson:"err,omitempty"`
	RanAt     time.Time    `json:"ran_at" bson:"ran_at"`
}

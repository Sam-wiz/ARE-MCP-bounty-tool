package types

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ============================================================================
// FINDING LIFECYCLE (v2) — the gated state machine
//
// The v1 engine treated a finding as VULNERABLE the moment a tool reported an
// indicator. That produced 105 self-labelled "VULNERABLE" vectors that paid
// ~$0. The v2 lifecycle only lets a finding advance once impact is proven and
// it survives an adversarial skeptic. Report generation is only permitted from
// SURVIVED_SKEPTIC onward, and SUBMIT_READY requires a human gate.
// ============================================================================

const (
	FindingCandidate      FindingState = "CANDIDATE"       // an indicator exists, nothing proven
	FindingReproduced     FindingState = "REPRODUCED"      // PoC actually runs and reproduces
	FindingImpactProven   FindingState = "IMPACT_PROVEN"   // demonstrates real impact, not just an indicator
	FindingSurvivedSkeptic FindingState = "SURVIVED_SKEPTIC" // passed the adversarial panel
	FindingReportDrafted  FindingState = "REPORT_DRAFTED"  // report written
	FindingSubmitReady    FindingState = "SUBMIT_READY"    // human approved for submission
	FindingSubmitted      FindingState = "SUBMITTED"       // sent to the program
	// Terminal outcomes (mirror the platform triager's verdict)
	FindingAccepted      FindingState = "ACCEPTED"       // paid / triaged as valid
	FindingDuplicate     FindingState = "DUPLICATE"      // already known
	FindingInformational FindingState = "INFORMATIONAL"  // valid but no bounty
	FindingNotApplicable FindingState = "NOT_APPLICABLE" // by-design / rejected as N/A
	FindingRejected      FindingState = "REJECTED"       // killed by skeptic before submission
)

// ============================================================================
// REVIEW — one adversarial panel pass over a finding
// ============================================================================

// ReviewVerdict is the mechanical, conservative aggregate the tool computes.
// It is a recommendation to the Claude Code session, NOT an autonomous decision.
type ReviewVerdict string

const (
	VerdictReject         ReviewVerdict = "REJECT"          // a credible panelist says it isn't real / is by-design
	VerdictRevise         ReviewVerdict = "REVISE"          // fixable: outstanding evidence-demands remain
	VerdictSubmitCandidate ReviewVerdict = "SUBMIT_CANDIDATE" // cleared the bar; still needs human gate to submit
)

// PanelVerdict is one model's adversarial assessment of a finding.
type PanelVerdict struct {
	Model               string   `json:"model" bson:"model"`
	IsReal              bool     `json:"is_real" bson:"is_real"`                             // is there an actual vulnerability?
	ImpactProven        bool     `json:"impact_proven" bson:"impact_proven"`                 // is impact demonstrated (not just an indicator)?
	InScope             bool     `json:"in_scope" bson:"in_scope"`                           // within the program's stated scope?
	ByDesign            bool     `json:"by_design" bson:"by_design"`                         // is this intended behaviour (e.g. public client key)?
	DuplicateLikelihood float64  `json:"duplicate_likelihood" bson:"duplicate_likelihood"`   // 0..1, how likely a triager marks it duplicate
	WorthMoney          bool     `json:"worth_money" bson:"worth_money"`                     // would a triager plausibly pay this?
	Confidence          float64  `json:"confidence" bson:"confidence"`                       // 0..1 self-reported confidence
	Verdict             ReviewVerdict `json:"verdict" bson:"verdict"`
	Flaws               []string `json:"flaws" bson:"flaws"`                                 // specific problems found
	EvidenceDemands     []string `json:"evidence_demands" bson:"evidence_demands"`           // falsifiable "prove X" requests
	Raw                 string   `json:"raw,omitempty" bson:"raw,omitempty"`                 // raw model output (for audit)
	Error               string   `json:"error,omitempty" bson:"error,omitempty"`            // set if the panelist call failed
}

// Review is the persisted record of a single review round.
type Review struct {
	ID              primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	FindingID       string             `json:"finding_id" bson:"finding_id"`
	Program         string             `json:"program" bson:"program"`
	SessionID       string             `json:"session_id" bson:"session_id"`
	Round           int                `json:"round" bson:"round"`
	Timestamp       time.Time          `json:"timestamp" bson:"timestamp"`
	Panel           []PanelVerdict     `json:"panel" bson:"panel"`
	Verdict         ReviewVerdict      `json:"verdict" bson:"verdict"`                   // mechanical aggregate
	EvidenceDemands []string           `json:"evidence_demands" bson:"evidence_demands"` // unioned, deduped demands to clear
	Rationale       string             `json:"rationale" bson:"rationale"`               // why the aggregate came out this way
	RequiresHuman   bool               `json:"requires_human" bson:"requires_human"`     // always true before SUBMIT_READY
}

// ============================================================================
// TRIAGE OUTCOME — the feedback loop. Real verdicts from the program.
// This is the single most valuable calibration signal and the thing v1 lacked.
// ============================================================================

// TriageState mirrors what a program's triager actually decided.
type TriageState string

const (
	TriageAccepted      TriageState = "ACCEPTED"
	TriageDuplicate     TriageState = "DUPLICATE"
	TriageInformational TriageState = "INFORMATIONAL"
	TriageNotApplicable TriageState = "NOT_APPLICABLE"
	TriagePending       TriageState = "PENDING"
)

// TriageOutcome records what happened after a finding was submitted.
type TriageOutcome struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	FindingID    string             `json:"finding_id" bson:"finding_id"`
	Program      string             `json:"program" bson:"program"`
	Platform     string             `json:"platform" bson:"platform"`         // hackerone, bugcrowd, ...
	PlatformRef  string             `json:"platform_ref" bson:"platform_ref"` // report id / url
	Title        string             `json:"title" bson:"title"`
	VulnType     string             `json:"vuln_type" bson:"vuln_type"`
	Severity     string             `json:"severity" bson:"severity"`
	State        TriageState        `json:"state" bson:"state"`
	RewardAmount float64            `json:"reward_amount" bson:"reward_amount"`
	Currency     string             `json:"currency" bson:"currency"`
	RejectReason string             `json:"reject_reason,omitempty" bson:"reject_reason,omitempty"` // why it was NA/dup/info
	Notes        string             `json:"notes,omitempty" bson:"notes,omitempty"`
	SubmittedAt  time.Time          `json:"submitted_at,omitempty" bson:"submitted_at,omitempty"`
	RecordedAt   time.Time          `json:"recorded_at" bson:"recorded_at"`
}

// ============================================================================
// LESSON — curated grounding for the reviewer (FP classes, past mistakes)
// ============================================================================

// Lesson is a durable "what not to do" derived from outcomes or authored by hand.
type Lesson struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Program   string             `json:"program,omitempty" bson:"program,omitempty"` // empty = global
	VulnType  string             `json:"vuln_type,omitempty" bson:"vuln_type,omitempty"`
	FPClass   string             `json:"fp_class,omitempty" bson:"fp_class,omitempty"` // e.g. "public-client-key"
	Lesson    string             `json:"lesson" bson:"lesson"`                         // the actual guidance
	Source    string             `json:"source,omitempty" bson:"source,omitempty"`     // finding_id / outcome / "manual"
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

// ============================================================================
// HYPOTHESIS — director output: an untried attack idea, NOT a finding
// ============================================================================

// Hypothesis is a proposed new attack vector the director hands to the engine
// when it is stuck. It must still pass the confirmation gate before it can
// become a candidate finding.
type Hypothesis struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Program   string             `json:"program" bson:"program"`
	VectorID  string             `json:"vector_id" bson:"vector_id"` // canonical id, checked against exhausted vectors
	Title     string             `json:"title" bson:"title"`
	Rationale string             `json:"rationale" bson:"rationale"`
	HowToTest string             `json:"how_to_test" bson:"how_to_test"`
	Priority  string             `json:"priority" bson:"priority"` // high, medium, low
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

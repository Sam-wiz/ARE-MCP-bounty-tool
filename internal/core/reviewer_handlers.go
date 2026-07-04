package core

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/director"
	"github.com/samrudh/hack-ai-v2/internal/llm"
	"github.com/samrudh/hack-ai-v2/internal/precheck"
	"github.com/samrudh/hack-ai-v2/internal/reviewer"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// ============================================================================
// review_report — run the adversarial panel over a candidate finding.
// The tool returns the panel's demands and a conservative aggregate for the
// Claude Code session to arbitrate. It never advances a finding to submit-ready
// (that is a human-gated step: mark_submit_ready).
// ============================================================================

func (e *Engine) handleReviewReport(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	if !e.reviewer.Available() {
		return errorResult("❌ No reviewer panel configured. Set OPENAI_API_KEY and/or NVIDIA_API_KEY in .env."), nil
	}

	program := argStr(args, "program")
	if program == "" {
		program = e.GetProgram()
	}

	in := reviewer.Input{
		Program:      program,
		SessionID:    e.getSessionID(),
		Title:        argStr(args, "title"),
		Severity:     argStr(args, "severity"),
		VulnType:     argStr(args, "vuln_type"),
		Target:       argStr(args, "target"),
		URL:          argStr(args, "url"),
		Description:  argStr(args, "description"),
		PoC:          argStr(args, "poc"),
		Evidence:     argStr(args, "evidence"),
		ProgramScope: argStr(args, "program_scope"),
	}

	// If a finding_id is given, hydrate the finding from storage.
	findingID := argStr(args, "finding_id")
	if findingID != "" && e.config.MongoDB != nil {
		if f, err := e.config.MongoDB.GetFinding(ctx, findingID); err == nil && f != nil {
			in.FindingID = f.ID
			if in.Program == "" {
				in.Program = f.Program
			}
			fillFromFinding(&in, f)
		}
	}

	if in.Title == "" && in.Description == "" {
		return errorResult("❌ Provide a finding_id, or inline title/description (+severity, vuln_type, url, poc, evidence)."), nil
	}

	// Cheap deterministic precheck FIRST — if it hard-disqualifies (out-of-scope
	// or own-duplicate), skip the expensive panel entirely (saves tokens/time).
	pc := e.runPrecheck(ctx, in)
	if pc.SkipPanel {
		return successResult(formatPrecheck(pc) + "\n⏭️  Panel skipped — resolve the disqualifier above or drop the finding. No LLM tokens spent."), nil
	}

	// Ground the panel: program scope + prior lessons for this program/class.
	if e.config.MongoDB != nil {
		if in.ProgramScope == "" && in.Program != "" {
			if p, err := e.config.MongoDB.GetProgram(ctx, in.Program); err == nil && p != nil {
				in.ProgramScope = formatScope(p)
			}
		}
		if lessons, err := e.config.MongoDB.GetLessons(ctx, in.Program, in.VulnType); err == nil {
			for _, l := range lessons {
				in.Lessons = append(in.Lessons, l.Lesson)
			}
		}
		// Lightweight semantic retrieval: pull the most similar real triager
		// verdicts from past submissions (brute-force cosine, top-3). Optional —
		// silently skipped if no embedder is configured or no threads embedded.
		in.PriorVerdicts = e.retrievePriorVerdicts(ctx, in.Title+" "+in.VulnType+" "+in.Description, 3)
		in.Round = 1
		if findingID != "" {
			in.Round = e.config.MongoDB.NextReviewRound(ctx, findingID)
		}
	}

	review, err := e.reviewer.Review(ctx, in)
	if err != nil {
		return errorResult(fmt.Sprintf("❌ Review failed: %v", err)), nil
	}

	// Persist the review and reflect the mechanical verdict into the finding's
	// state — but only in the two safe directions. REVISE never changes state,
	// and we never set SUBMIT_READY here (human gate).
	if e.config.MongoDB != nil {
		_ = e.config.MongoDB.SaveReview(ctx, review)
		if findingID != "" && review.Verdict == types.VerdictSubmitCandidate {
			// Only a cleared review advances state. A blocker is NOT terminal —
			// the finding stays alive to be solved or explicitly dropped, so we
			// never auto-transition to REJECTED here.
			_ = e.config.MongoDB.UpdateFindingState(ctx, findingID, types.FindingSurvivedSkeptic)
		}
	}

	// Prepend the precheck summary (FP-class warnings, value score) so the
	// agent sees the cheap signals alongside the panel verdict.
	out := formatReview(review, e.reviewer.ModelNames())
	if len(pc.Warnings) > 0 {
		out = formatPrecheck(pc) + "\n" + out
	}
	return successResult(out), nil
}

func fillFromFinding(in *reviewer.Input, f *types.Finding) {
	if in.Title == "" {
		in.Title = f.Title
	}
	if in.Description == "" {
		in.Description = f.Description
	}
	if in.Severity == "" {
		in.Severity = f.Severity
	}
	if in.VulnType == "" {
		in.VulnType = f.VulnType
	}
	if in.Target == "" {
		in.Target = f.Target
	}
	if in.URL == "" {
		in.URL = f.URL
	}
	if in.PoC == "" {
		in.PoC = formatPoC(f)
	}
	if in.Evidence == "" && len(f.Evidence) > 0 {
		in.Evidence = strings.Join(f.Evidence, "\n")
	}
}

func formatPoC(f *types.Finding) string {
	if f.PoC == nil {
		return ""
	}
	var b strings.Builder
	p := f.PoC
	if p.Description != "" {
		fmt.Fprintf(&b, "%s\n", p.Description)
	}
	if p.CurlCommand != "" {
		fmt.Fprintf(&b, "curl: %s\n", p.CurlCommand)
	}
	if p.Request != "" {
		fmt.Fprintf(&b, "request:\n%s\n", p.Request)
	}
	for _, s := range p.Steps {
		fmt.Fprintf(&b, "- %s\n", s)
	}
	if p.ActualResult != "" {
		fmt.Fprintf(&b, "actual result: %s\n", p.ActualResult)
	}
	return b.String()
}

func formatReview(r *types.Review, panelModels []string) string {
	var b strings.Builder
	emoji := map[types.ReviewVerdict]string{
		types.VerdictReject:          "⛔",
		types.VerdictRevise:          "🔧",
		types.VerdictSubmitCandidate: "🎯",
	}[r.Verdict]
	// A blocker is a hard objection to SOLVE or DROP — not a terminal rejection.
	label := map[types.ReviewVerdict]string{
		types.VerdictReject:          "BLOCKED (solve the objection or drop)",
		types.VerdictRevise:          "REVISE (clear the demands)",
		types.VerdictSubmitCandidate: "SUBMIT_CANDIDATE (cleared the bar)",
	}[r.Verdict]

	b.WriteString(fmt.Sprintf("%s PANEL VERDICT: %s  (round %d)\n", emoji, label, r.Round))
	b.WriteString(fmt.Sprintf("Panel: %s\n\n", strings.Join(panelModels, ", ")))

	for _, v := range r.Panel {
		if v.Error != "" {
			b.WriteString(fmt.Sprintf("  • %s — ⚠️ error: %s\n", v.Model, v.Error))
			continue
		}
		b.WriteString(fmt.Sprintf("  • %s → %s (conf %.0f%%) | real=%v impact=%v scope=%v by_design=%v dup=%.0f%% pay=%v\n",
			v.Model, v.Verdict, v.Confidence*100, v.IsReal, v.ImpactProven, v.InScope, v.ByDesign, v.DuplicateLikelihood*100, v.WorthMoney))
		for _, fl := range v.Flaws {
			b.WriteString(fmt.Sprintf("        flaw: %s\n", fl))
		}
	}

	b.WriteString(fmt.Sprintf("\nAggregate rationale: %s\n", r.Rationale))

	if len(r.EvidenceDemands) > 0 {
		b.WriteString("\n📋 EVIDENCE-DEMANDS TO CLEAR (do not dismiss — prove each or drop the finding):\n")
		for i, d := range r.EvidenceDemands {
			b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, d))
		}
	}

	b.WriteString("\n— Arbitration is YOURS (you hold the most context). The panel raises the bar; you clear it or drop the finding.\n")
	switch r.Verdict {
	case types.VerdictReject:
		b.WriteString("— A credible panelist raised a hard BLOCKER. This is NOT a rejection and the finding is NOT killed.\n")
		b.WriteString("— Solve it: rebut the objection with evidence, or fix the finding, then re-run review_report for the next round.\n")
		b.WriteString("— If the blocker genuinely can't be solved (e.g. it really is by-design), drop it with log_triage_outcome state=NOT_APPLICABLE.\n")
	case types.VerdictRevise:
		b.WriteString("— Clear the demands above, then run review_report again for the next round.\n")
	case types.VerdictSubmitCandidate:
		b.WriteString("— Cleared the bar → state advanced to SURVIVED_SKEPTIC. Still requires human approval: call mark_submit_ready when the human OKs it.\n")
	}
	return b.String()
}

// ============================================================================
// request_horizon — director proposes NEW untried hypotheses when stuck.
// ============================================================================

func (e *Engine) handleRequestHorizon(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	if !e.director.Available() {
		return errorResult("❌ No director model configured. Set DIRECTOR_PROVIDER/DIRECTOR_MODEL (+ matching API key) in .env."), nil
	}
	program := e.GetProgram()
	if program == "" {
		return errorResult("❌ No active program. Call set_program first."), nil
	}

	in := director.Input{
		Program: program,
		Notes:   argStr(args, "notes"),
		Max:     int(argFloat(args, "max")),
	}

	// Feed the director the exploration ledger so it can't re-tread dead ground.
	if e.config.MongoDB != nil {
		if p, err := e.config.MongoDB.GetProgram(ctx, program); err == nil && p != nil {
			in.Scope = formatScope(p)
		}
		if statuses, err := e.config.MongoDB.GetVectorStatuses(ctx, program); err == nil {
			seen := map[string]bool{}
			for _, s := range statuses { // sorted newest-first → first per vector is latest
				if seen[s.VectorID] {
					continue
				}
				seen[s.VectorID] = true
				switch s.State {
				case "EXHAUSTED":
					in.Exhausted = append(in.Exhausted, s.VectorID)
				case "BLOCKED_BY_DESIGN":
					in.Blocked = append(in.Blocked, s.VectorID)
				case "VULNERABLE":
					in.Vulnerable = append(in.Vulnerable, s.VectorID)
				}
			}
		}
	}

	hyps, err := e.director.Horizon(ctx, in)
	if err != nil {
		return errorResult(fmt.Sprintf("❌ Director failed: %v", err)), nil
	}
	if len(hyps) == 0 {
		return successResult("Director returned no NEW hypotheses (all proposals collided with already-explored vectors). The surface may be genuinely exhausted."), nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("🧭 NEW HORIZONS from %s (%d hypotheses — these are UNVERIFIED ideas to test, not findings):\n\n", e.director.ModelName(), len(hyps)))
	for i := range hyps {
		h := &hyps[i]
		if e.config.MongoDB != nil {
			_ = e.config.MongoDB.SaveHypothesis(ctx, h)
		}
		b.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, strings.ToUpper(h.Priority), h.Title))
		b.WriteString(fmt.Sprintf("   vector_id: %s\n", h.VectorID))
		b.WriteString(fmt.Sprintf("   why: %s\n", h.Rationale))
		b.WriteString(fmt.Sprintf("   test: %s\n\n", h.HowToTest))
	}
	b.WriteString("Each hypothesis still has to pass the confirmation gate (reproduce → prove impact → review_report) before it can become a finding.\n")
	return successResult(b.String()), nil
}

// ============================================================================
// log_triage_outcome — the feedback loop. Record real submission verdicts.
// ============================================================================

func (e *Engine) handleLogTriageOutcome(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	if e.config.MongoDB == nil {
		return errorResult("❌ MongoDB not available — cannot record outcome."), nil
	}

	stateRaw := strings.ToUpper(strings.TrimSpace(argStr(args, "state")))
	valid := map[string]types.TriageState{
		"ACCEPTED":       types.TriageAccepted,
		"DUPLICATE":      types.TriageDuplicate,
		"INFORMATIONAL":  types.TriageInformational,
		"NOT_APPLICABLE": types.TriageNotApplicable,
		"NA":             types.TriageNotApplicable,
		"PENDING":        types.TriagePending,
	}
	state, ok := valid[stateRaw]
	if !ok {
		return errorResult("❌ 'state' must be ACCEPTED, DUPLICATE, INFORMATIONAL, NOT_APPLICABLE, or PENDING."), nil
	}

	program := argStr(args, "program")
	if program == "" {
		program = e.GetProgram()
	}

	outcome := &types.TriageOutcome{
		FindingID:    argStr(args, "finding_id"),
		Program:      program,
		Platform:     argStr(args, "platform"),
		PlatformRef:  argStr(args, "platform_ref"),
		Title:        argStr(args, "title"),
		VulnType:     argStr(args, "vuln_type"),
		Severity:     argStr(args, "severity"),
		State:        state,
		RewardAmount: argFloat(args, "reward_amount"),
		Currency:     argStr(args, "currency"),
		RejectReason: argStr(args, "reject_reason"),
		Notes:        argStr(args, "notes"),
		RecordedAt:   time.Now(),
	}
	if outcome.Currency == "" && outcome.RewardAmount > 0 {
		outcome.Currency = "USD"
	}
	if err := e.config.MongoDB.LogTriageOutcome(ctx, outcome); err != nil {
		return errorResult(fmt.Sprintf("❌ Failed to log outcome: %v", err)), nil
	}

	// Mirror into the finding's terminal state.
	if outcome.FindingID != "" {
		term := map[types.TriageState]types.FindingState{
			types.TriageAccepted:      types.FindingAccepted,
			types.TriageDuplicate:     types.FindingDuplicate,
			types.TriageInformational: types.FindingInformational,
			types.TriageNotApplicable: types.FindingNotApplicable,
		}
		if fs, ok := term[state]; ok {
			_ = e.config.MongoDB.UpdateFindingState(ctx, outcome.FindingID, fs)
		}
	}

	// A rejection with a reason is a durable lesson — capture it automatically.
	var lessonNote string
	if outcome.RejectReason != "" && (state == types.TriageNotApplicable || state == types.TriageInformational || state == types.TriageDuplicate) {
		_ = e.config.MongoDB.SaveLesson(ctx, &types.Lesson{
			Program:  program,
			VulnType: outcome.VulnType,
			FPClass:  strings.ToLower(string(state)),
			Lesson:   fmt.Sprintf("[%s] %s → closed %s: %s", program, outcome.Title, state, outcome.RejectReason),
			Source:   outcome.FindingID,
		})
		lessonNote = "\n📚 A lesson was recorded from this rejection — the reviewer will apply it to future findings of this class."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("✅ Outcome recorded: %s → %s", program, state))
	if outcome.RewardAmount > 0 {
		b.WriteString(fmt.Sprintf(" (%.2f %s)", outcome.RewardAmount, outcome.Currency))
	}
	b.WriteString("\nThis is the calibration signal — it feeds review_stats (the real scoreboard) and grounds future reviews.")
	b.WriteString(lessonNote)
	return successResult(b.String()), nil
}

// ============================================================================
// mark_submit_ready — the human gate. Refuses to advance without confirmation.
// ============================================================================

func (e *Engine) handleMarkSubmitReady(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	findingID := argStr(args, "finding_id")
	if findingID == "" {
		return errorResult("❌ 'finding_id' is required."), nil
	}
	if !argBool(args, "human_confirm") {
		// Record the request for a human decision; do NOT advance.
		if e.config.MongoDB != nil {
			_ = e.config.MongoDB.LogConsultation(ctx, &types.Consultation{
				Program:   e.GetProgram(),
				SessionID: e.getSessionID(),
				Question:  fmt.Sprintf("Approve finding %s for submission?", findingID),
				Context:   argStr(args, "note"),
				Urgency:   "blocking",
				Category:  "approval",
			})
		}
		return errorResult("🛑 HUMAN GATE: submission requires explicit approval.\n" +
			"A human must confirm before this finding is marked SUBMIT_READY.\n" +
			"Re-call with human_confirm=true only after the human has approved."), nil
	}

	if e.config.MongoDB != nil {
		if err := e.config.MongoDB.UpdateFindingState(ctx, findingID, types.FindingSubmitReady); err != nil {
			return errorResult(fmt.Sprintf("❌ Failed to update state: %v", err)), nil
		}
	}
	return successResult(fmt.Sprintf("✅ Finding %s marked SUBMIT_READY (human-approved). Submit it, then record the result with log_triage_outcome.", findingID)), nil
}

// ============================================================================
// record_lesson — manually capture an FP-class / mistake for grounding.
// ============================================================================

func (e *Engine) handleRecordLesson(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	lesson := argStr(args, "lesson")
	if lesson == "" {
		return errorResult("❌ 'lesson' is required — the guidance to remember."), nil
	}
	if e.config.MongoDB == nil {
		return errorResult("❌ MongoDB not available — cannot store lesson."), nil
	}
	l := &types.Lesson{
		Program:  argStr(args, "program"), // empty = global
		VulnType: argStr(args, "vuln_type"),
		FPClass:  argStr(args, "fp_class"),
		Lesson:   lesson,
		Source:   "manual",
	}
	if err := e.config.MongoDB.SaveLesson(ctx, l); err != nil {
		return errorResult(fmt.Sprintf("❌ Failed to save lesson: %v", err)), nil
	}
	scope := l.Program
	if scope == "" {
		scope = "global"
	}
	return successResult(fmt.Sprintf("📚 Lesson saved (%s). Future reviews of matching findings will apply it.", scope)), nil
}

// ============================================================================
// review_stats — the REAL scoreboard, computed from triage outcomes.
// ============================================================================

func (e *Engine) handleReviewStats(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	if e.config.MongoDB == nil {
		return errorResult("❌ MongoDB not available."), nil
	}
	program := argStr(args, "program") // empty = all
	stats, err := e.config.MongoDB.GetOutcomeStats(ctx, program)
	if err != nil {
		return errorResult(fmt.Sprintf("❌ Failed to compute stats: %v", err)), nil
	}

	scope := program
	if scope == "" {
		scope = "ALL PROGRAMS"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("📊 REAL SCOREBOARD — %s (from triage outcomes, not self-labels)\n\n", scope))
	if stats.Total == 0 {
		b.WriteString("No triage outcomes recorded yet. Log real verdicts with log_triage_outcome to build the scoreboard.\n")
		return successResult(b.String()), nil
	}
	b.WriteString(fmt.Sprintf("Submissions with outcomes: %d\n", stats.Total))
	b.WriteString(fmt.Sprintf("Accepted / paid:           %d\n", stats.PaidCount))
	b.WriteString(fmt.Sprintf("Accept rate (paid):        %.1f%%\n", stats.AcceptRate*100))
	b.WriteString(fmt.Sprintf("Valid rate (accepted+dup): %.1f%%  (%d were real; dups were correct but not first)\n", stats.ValidRate*100, stats.ValidCount))
	b.WriteString(fmt.Sprintf("Total reward:              %.2f\n\n", stats.TotalReward))
	b.WriteString("By outcome:\n")
	for _, k := range []string{"ACCEPTED", "DUPLICATE", "INFORMATIONAL", "NOT_APPLICABLE", "PENDING"} {
		if c := stats.ByState[k]; c > 0 {
			b.WriteString(fmt.Sprintf("  %-15s %d\n", k, c))
		}
	}
	if len(stats.RewardByType) > 0 {
		b.WriteString("\nReward by vuln type (accepted):\n")
		for t, amt := range stats.RewardByType {
			if t == "" {
				t = "(unspecified)"
			}
			b.WriteString(fmt.Sprintf("  %-24s %.2f\n", t, amt))
		}
	}
	return successResult(b.String()), nil
}

// ============================================================================
// helpers
// ============================================================================

// retrievePriorVerdicts embeds the query and returns the top-k most similar
// past triager verdicts (by cosine over stored thread embeddings). Returns nil
// on any miss — it's an optional enrichment, never a hard dependency.
func (e *Engine) retrievePriorVerdicts(ctx context.Context, query string, k int) []string {
	if e.config.MongoDB == nil {
		return nil
	}
	embedder, ok := llm.EmbedderFromEnv()
	if !ok {
		return nil
	}
	vecs, err := e.config.MongoDB.AllThreadVecs(ctx)
	if err != nil || len(vecs) == 0 {
		return nil
	}
	qv, err := embedder.Embed(ctx, query)
	if err != nil {
		return nil
	}

	type scored struct {
		snip  string
		score float64
	}
	ranked := make([]scored, 0, len(vecs))
	for _, v := range vecs {
		if len(v.Embedding) == 0 || v.Snippet == "" {
			continue
		}
		ranked = append(ranked, scored{v.Snippet, llm.Cosine(qv, v.Embedding)})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })

	var out []string
	for i := 0; i < len(ranked) && i < k; i++ {
		if ranked[i].score < 0.3 { // ignore weak matches
			break
		}
		out = append(out, ranked[i].snip)
	}
	return out
}

// runPrecheck builds precheck input from the review input + program context.
func (e *Engine) runPrecheck(ctx context.Context, in reviewer.Input) precheck.Result {
	pin := precheck.Input{
		Title: in.Title, Description: in.Description, PoC: in.PoC, Evidence: in.Evidence,
		VulnType: in.VulnType, Severity: in.Severity, Target: in.Target, URL: in.URL,
	}
	if e.config.MongoDB != nil && in.Program != "" {
		if p, err := e.config.MongoDB.GetProgram(ctx, in.Program); err == nil && p != nil {
			pin.InScope = p.Scope.InScope
			pin.OutOfScope = p.Scope.OutOfScope
			pin.PayoutMax = p.PayoutMax
		}
		// Own-duplicate keys: prior submitted/accepted outcomes for this program.
		if outs, err := e.config.MongoDB.GetTriageOutcomes(ctx, in.Program); err == nil {
			for _, o := range outs {
				pin.PriorKeys = append(pin.PriorKeys, o.VulnType+"|"+o.Program)
			}
		}
	}
	return precheck.Check(pin)
}

func formatPrecheck(pc precheck.Result) string {
	var b strings.Builder
	icon := "✅"
	if pc.Verdict == precheck.Disqualified {
		icon = "⛔"
	}
	b.WriteString(fmt.Sprintf("%s PRECHECK: %s  (value score %.0f)\n", icon, pc.Verdict, pc.ValueScore))
	for _, r := range pc.Reasons {
		b.WriteString("   ⛔ " + r + "\n")
	}
	for _, w := range pc.Warnings {
		b.WriteString("   ⚠️  " + w + "\n")
	}
	return b.String()
}

// precheck_finding — run only the cheap deterministic precheck (no LLM).
func (e *Engine) handlePrecheckFinding(ctx context.Context, args map[string]interface{}) (types.ToolResult, error) {
	program := argStr(args, "program")
	if program == "" {
		program = e.GetProgram()
	}
	in := reviewer.Input{
		Program: program, Title: argStr(args, "title"), Severity: argStr(args, "severity"),
		VulnType: argStr(args, "vuln_type"), Target: argStr(args, "target"), URL: argStr(args, "url"),
		Description: argStr(args, "description"), PoC: argStr(args, "poc"), Evidence: argStr(args, "evidence"),
	}
	if fid := argStr(args, "finding_id"); fid != "" && e.config.MongoDB != nil {
		if f, err := e.config.MongoDB.GetFinding(ctx, fid); err == nil && f != nil {
			if in.Program == "" {
				in.Program = f.Program
			}
			fillFromFinding(&in, f)
		}
	}
	if in.Title == "" && in.Description == "" {
		return errorResult("❌ Provide finding_id or inline title/description."), nil
	}
	pc := e.runPrecheck(ctx, in)
	out := formatPrecheck(pc)
	if pc.Verdict == precheck.Proceed {
		out += "\n→ Passed precheck. Run review_report for the adversarial panel."
	} else {
		out += "\n⏭️  Disqualified deterministically — no LLM tokens needed. Resolve or drop."
	}
	return successResult(out), nil
}

func formatScope(p *types.BountyProgram) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Platform: %s  Payout: %d-%d\n", p.Platform, p.PayoutMin, p.PayoutMax)
	if len(p.Scope.InScope) > 0 {
		fmt.Fprintf(&b, "In scope: %s\n", strings.Join(p.Scope.InScope, ", "))
	}
	if len(p.Scope.OutOfScope) > 0 {
		fmt.Fprintf(&b, "Out of scope: %s\n", strings.Join(p.Scope.OutOfScope, ", "))
	}
	if len(p.Scope.Restrictions) > 0 {
		fmt.Fprintf(&b, "Restrictions: %s\n", strings.Join(p.Scope.Restrictions, ", "))
	}
	if len(p.Rules) > 0 {
		fmt.Fprintf(&b, "Rules: %s\n", strings.Join(p.Rules, "; "))
	}
	return b.String()
}

func argStr(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func argFloat(args map[string]interface{}, key string) float64 {
	v, ok := args[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f
	}
	return 0
}

func argBool(args map[string]interface{}, key string) bool {
	v, ok := args[key]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(strings.TrimSpace(b), "true")
	}
	return false
}

package precheck

import "testing"

func TestPrecheck_OutOfScopeDisqualifies(t *testing.T) {
	r := Check(Input{
		Title: "IDOR", Description: "idor", VulnType: "idor",
		Target: "evil.com", Severity: "P2",
		InScope: []string{"*.example.com"}, PayoutMax: 10000,
	})
	if r.Verdict != Disqualified || !r.SkipPanel {
		t.Fatalf("out-of-scope should be DISQUALIFIED+SkipPanel, got %s skip=%v", r.Verdict, r.SkipPanel)
	}
}

func TestPrecheck_FPClassWarnsButProceeds(t *testing.T) {
	r := Check(Input{
		Title: "Secret", Description: "NEXT_PUBLIC_BRAINTREE_TOKENIZATION_KEY in bundle",
		VulnType: "secret-exposure", Target: "app.example.com", Severity: "P2",
		InScope: []string{"*.example.com"}, PayoutMax: 10000,
	})
	if r.Verdict != Proceed {
		t.Fatalf("FP-class must NOT hard-block a possibly-real finding, got %s", r.Verdict)
	}
	if len(r.FPClasses) == 0 || r.FPClasses[0] != "public-client-key" {
		t.Fatalf("expected public-client-key FP class, got %v", r.FPClasses)
	}
	if r.ValueScore >= 40000 { // penalty must lower it from full 10000*4
		t.Fatalf("FP-class should deprioritize value, got %.0f", r.ValueScore)
	}
}

func TestPrecheck_CleanProceedsHighValue(t *testing.T) {
	r := Check(Input{
		Title:       "Cross-tenant IDOR",
		Description: "GET /api/v1/orders/{id} returns other tenants' orders. Steps: 1. login 2. curl. Impact: attacker can read all orders. PoC: curl returns 200 with victim data.",
		VulnType:    "idor", Target: "api.example.com", Severity: "P1",
		InScope: []string{"*.example.com"}, PayoutMax: 10000,
	})
	if r.Verdict != Proceed || len(r.FPClasses) != 0 {
		t.Fatalf("clean finding should PROCEED with no FP class, got %s %v", r.Verdict, r.FPClasses)
	}
	if !r.Completeness["has_repro"] || !r.Completeness["has_poc"] || !r.Completeness["has_impact"] {
		t.Fatalf("clean finding should pass completeness, got %v", r.Completeness)
	}
	if r.ValueScore != 50000 { // 10000 * 5 (P1)
		t.Fatalf("expected value 50000, got %.0f", r.ValueScore)
	}
}

func TestPrecheck_OwnDuplicate(t *testing.T) {
	r := Check(Input{
		Title: "SSRF", Description: "ssrf", VulnType: "ssrf", Target: "api.example.com",
		Severity: "P2", InScope: []string{"*.example.com"},
		PriorKeys: []string{"ssrf|api.example.com"},
	})
	if r.Verdict != Disqualified {
		t.Fatalf("own-duplicate should be DISQUALIFIED, got %s", r.Verdict)
	}
}

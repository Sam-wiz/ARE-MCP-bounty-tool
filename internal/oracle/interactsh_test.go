package oracle

import "testing"

func TestParsePayloadDomain(t *testing.T) {
	cases := map[string]string{
		"[INF] c8k9q1m2n3p4r5s6t7u8.oast.fun":              "c8k9q1m2n3p4r5s6t7u8.oast.fun",
		"Listing 1 payload for OOB Testing":                "",
		"cabcdefghijklmnop1234.oast.online is your domain": "cabcdefghijklmnop1234.oast.online",
		"no domain here": "",
	}
	for line, want := range cases {
		if got := parsePayloadDomain(line); got != want {
			t.Errorf("parsePayloadDomain(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestLineWithToken(t *testing.T) {
	log := `{"protocol":"dns","unique-id":"c8k9q1","full-id":"deadbeefc8k9q1","remote-address":"1.2.3.4"}
[INF] some unrelated log line mentioning deadbeef but not an interaction
{"protocol":"http","full-id":"cafef00dc8k9q1","remote-address":"5.6.7.8"}`

	// A token that appears inside a real interaction record → match.
	if got := lineWithToken(log, "deadbeef"); got == "" {
		t.Fatalf("expected a match for token in an interaction record")
	}
	// A token only present in a non-interaction log line → no match.
	if got := lineWithToken(log, "unrelated"); got != "" {
		t.Fatalf("expected no match for token only in noise line, got %q", got)
	}
	// Absent token → no match.
	if got := lineWithToken(log, "zzzznope"); got != "" {
		t.Fatalf("expected no match for absent token, got %q", got)
	}
}

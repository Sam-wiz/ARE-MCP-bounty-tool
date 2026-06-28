package core

import (
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// TestMatchPattern_PathScopedEntries locks in the fix for path-scoped scope
// entries (e.g. "host/testing-path/"), which previously could never match
// because URLs were stripped to a bare host before comparison.
func TestMatchPattern_PathScopedEntries(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		pattern string
		want    bool
	}{
		{"path entry matches url under that path", "https://www.developersites.com.au/testing-2505-lms/foo", "www.developersites.com.au/testing-2505-lms/", true},
		{"path entry rejects other path on same host", "https://www.developersites.com.au/other", "www.developersites.com.au/testing-2505-lms/", false},
		{"host-only entry matches any path", "https://www.developersites.com.au/anything/here", "www.developersites.com.au", true},
		{"wildcard matches subdomain", "https://sub.example.com/x", "*.example.com", true},
		{"wildcard matches apex", "https://example.com/x", "*.example.com", true},
		{"case-insensitive host", "HTTPS://WWW.EXAMPLE.COM/x", "www.example.com", true},
		{"different host never matches", "https://evil.com/testing-2505-lms/", "www.developersites.com.au/testing-2505-lms/", false},
	}
	for _, c := range cases {
		if got := matchPattern(c.target, c.pattern); got != c.want {
			t.Errorf("%s: matchPattern(%q, %q) = %v, want %v", c.name, c.target, c.pattern, got, c.want)
		}
	}
}

// TestValidateURLScope_PathScopedInScope proves the enforcer (used by
// http_request/api_test) honors a path-scoped in-scope entry end-to-end.
func TestValidateURLScope_PathScopedInScope(t *testing.T) {
	e := &Engine{}
	e.setActiveScope(types.Scope{
		InScope: []string{"www.developersites.com.au/testing-2505-lms/"},
	})

	if err := e.validateURLScope("https://www.developersites.com.au/testing-2505-lms/api/leads"); err != nil {
		t.Errorf("expected in-scope path to be allowed, got: %v", err)
	}
	if err := e.validateURLScope("https://www.developersites.com.au/admin"); err == nil {
		t.Errorf("expected out-of-path URL on same host to be blocked, but it was allowed")
	}
	if err := e.validateURLScope("https://other.com.au/testing-2505-lms/"); err == nil {
		t.Errorf("expected different host to be blocked, but it was allowed")
	}
}

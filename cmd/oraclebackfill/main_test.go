package main

import "testing"

func TestOracleClass(t *testing.T) {
	cases := []struct{ vt, vrt, want string }{
		{"ssrf", "", "ssrf"},
		{"idor", "Broken Object Level Authorization", "idor"},
		{"cors", "", "cors"},
		{"open-redirect", "", "open_redirect"},
		{"2fa-bypass", "Broken Authentication", "auth_bypass"},
		{"xss", "Cross-Site Scripting", ""},
		{"sqli", "", ""},
	}
	for _, c := range cases {
		if got := oracleClass(c.vt, c.vrt); got != c.want {
			t.Errorf("oracleClass(%q,%q)=%q want %q", c.vt, c.vrt, got, c.want)
		}
	}
}

func TestIsLiveHTTPTarget(t *testing.T) {
	if isLiveHTTPTarget("https://github.com/freedomofpress/securedrop", "securedrop/models.py") {
		t.Error("github source target must not be live-HTTP")
	}
	if isLiveHTTPTarget("https://api.example.com", "/v1/users/1") == false {
		t.Error("live API target should be live-HTTP")
	}
	if isLiveHTTPTarget("https://app.example.com", "app/routes.py") {
		t.Error("source-file url should disqualify")
	}
	// bare hostnames and wildcards are live HTTP
	if !isLiveHTTPTarget("opensea.io", "/collections") {
		t.Error("bare hostname should be live-HTTP")
	}
	if !isLiveHTTPTarget("*.immutable.com", "") {
		t.Error("wildcard host should be live-HTTP")
	}
	// product / SDK / mobile names are not hostnames
	if isLiveHTTPTarget("USAA Mobile Application for Android", "") {
		t.Error("mobile app name must not be live-HTTP")
	}
	if isLiveHTTPTarget("Zendesk Suite", "") {
		t.Error("product name must not be live-HTTP")
	}
}

func TestClassifyBuckets(t *testing.T) {
	// source-code review of a supported class → not_live_http
	s := submission{VulnType: "2fa-bypass", VRT: "Broken Authentication",
		Target: "https://github.com/x/y", URL: "y/models.py"}
	if c := classify(s); c.Bucket != bucketNotHTTP {
		t.Errorf("expected not_live_http, got %s", c.Bucket)
	}

	// unsupported class → unsupported_class
	s = submission{VulnType: "xss", Target: "https://app.example.com"}
	if c := classify(s); c.Bucket != bucketUnsupported {
		t.Errorf("expected unsupported_class, got %s", c.Bucket)
	}

	// supported + live + concrete request → replayable_candidate
	s = submission{VulnType: "idor", Target: "https://api.example.com", URL: "/v1/users/2",
		Messages: []message{{Body: "curl -H 'Authorization: Bearer x' https://api.example.com/v1/users/2"}}}
	if c := classify(s); c.Bucket != bucketReplayable {
		t.Errorf("expected replayable_candidate, got %s (%s)", c.Bucket, c.Reason)
	}

	// supported + live but no request → needs_manual_spec
	s = submission{VulnType: "idor", Target: "https://api.example.com", URL: "/v1/users/2",
		Messages: []message{{Body: "The endpoint leaks other users' data."}}}
	if c := classify(s); c.Bucket != bucketManual {
		t.Errorf("expected needs_manual_spec, got %s", c.Bucket)
	}
}

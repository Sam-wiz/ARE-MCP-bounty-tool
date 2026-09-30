// Command oraclebackfill classifies historical Bugcrowd submissions by whether
// the success oracle (M1) could replay them — the honest first step of building
// the reproducibility dataset (DATA_PLAN.md).
//
// It does NOT fake replays: most historical reports are source-code reviews or
// classes the v1 oracle set doesn't cover, and their targets/creds are gone. So
// the deliverable is a COVERAGE report — how much of the corpus the oracle can
// even touch — written to ORACLE_BACKFILL.md.
//
//	go run ./cmd/oraclebackfill [submissions.json] [out.md]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type message struct {
	Body string `json:"body"`
}

type submission struct {
	SubmissionID string    `json:"submission_id"`
	Title        string    `json:"title"`
	Program      string    `json:"program"`
	Target       string    `json:"target"`
	URL          string    `json:"url"`
	VRT          string    `json:"vrt"`
	VulnType     string    `json:"vuln_type"`
	Severity     string    `json:"severity"`
	State        string    `json:"state"`
	Messages     []message `json:"messages"`
}

// classification of one submission's oracle-replayability.
type classification struct {
	Class  string // oracle class, or "" if unsupported
	Bucket string // replayable_candidate | needs_manual_spec | not_live_http | unsupported_class
	Reason string
}

const (
	bucketReplayable  = "replayable_candidate"
	bucketManual      = "needs_manual_spec"
	bucketNotHTTP     = "not_live_http"
	bucketUnsupported = "unsupported_class"
)

var reqMarkerRE = regexp.MustCompile(`(?i)(curl\s+-|curl\s+http|^\s*(GET|POST|PUT|PATCH|DELETE)\s+/|HTTP/1\.[01]|Authorization:\s|\bfetch\(|XMLHttpRequest)`)

// oracleClass maps a submission's vuln_type/vrt to a supported oracle class.
func oracleClass(vulnType, vrt string) string {
	s := strings.ToLower(vulnType + " " + vrt)
	switch {
	case strings.Contains(s, "ssrf") || strings.Contains(s, "server-side request forgery"):
		return "ssrf"
	case strings.Contains(s, "idor") || strings.Contains(s, "insecure direct object") ||
		strings.Contains(s, "object level") || strings.Contains(s, "bola") || strings.Contains(s, "broken object"):
		return "idor"
	case strings.Contains(s, "cors") || strings.Contains(s, "cross-origin resource sharing"):
		return "cors"
	case strings.Contains(s, "open redirect") || strings.Contains(s, "open-redirect"):
		return "open_redirect"
	case strings.Contains(s, "auth") || strings.Contains(s, "access control") ||
		strings.Contains(s, "2fa") || strings.Contains(s, "privilege") || strings.Contains(s, "session"):
		return "auth_bypass"
	default:
		return ""
	}
}

var hostnameRE = regexp.MustCompile(`^([a-z0-9_-]+\.)+[a-z]{2,}$`)

// isLiveHTTPTarget reports whether the target is a testable live HTTP asset. It
// accepts full URLs, bare hostnames, and wildcards (*.example.com), but excludes
// source-code review targets (GitHub/GitLab repos, file paths) and non-web
// assets (mobile apps, SDK/library names, product names without a hostname).
func isLiveHTTPTarget(target, url string) bool {
	if strings.Contains(strings.ToLower(target), "github.com") ||
		strings.Contains(strings.ToLower(target), "gitlab.com") ||
		strings.Contains(strings.ToLower(target), "bitbucket.org") {
		return false
	}
	// url field pointing at a source file is a strong "code review" signal
	u := strings.ToLower(url)
	for _, ext := range []string{".py", ".js", ".ts", ".go", ".rb", ".java", ".php"} {
		if strings.Contains(u, ext) {
			return false
		}
	}
	// reduce the target to a host: strip scheme, wildcard, and any path/space.
	t := strings.ToLower(strings.TrimSpace(target))
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "*.")
	if i := strings.IndexAny(t, "/ ("); i >= 0 {
		t = t[:i]
	}
	return hostnameRE.MatchString(t)
}

func classify(s submission) classification {
	class := oracleClass(s.VulnType, s.VRT)
	if class == "" {
		return classification{Bucket: bucketUnsupported, Reason: "vuln_type/vrt not in oracle v1 set (cors/idor/auth_bypass/open_redirect/ssrf)"}
	}
	if !isLiveHTTPTarget(s.Target, s.URL) {
		return classification{Class: class, Bucket: bucketNotHTTP, Reason: "target is source-code / non-live-HTTP (can't be replayed against a live endpoint)"}
	}
	var body strings.Builder
	for _, m := range s.Messages {
		body.WriteString(m.Body)
		body.WriteByte('\n')
	}
	if !reqMarkerRE.MatchString(body.String()) {
		return classification{Class: class, Bucket: bucketManual, Reason: "supported class + live target, but no concrete HTTP request/curl found in the report to reconstruct a replay_spec"}
	}
	return classification{Class: class, Bucket: bucketReplayable, Reason: "supported class, live HTTP target, and a concrete request is present — a replay_spec can be reconstructed"}
}

func main() {
	in := "BUGCROWD_SUBMISSIONS.md"
	out := "ORACLE_BACKFILL.md"
	if len(os.Args) > 1 {
		in = os.Args[1]
	}
	if len(os.Args) > 2 {
		out = os.Args[2]
	}

	raw, err := os.ReadFile(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	var subs []submission
	if err := json.Unmarshal(raw, &subs); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	buckets := map[string]int{}
	byClass := map[string]int{}
	var rows []string
	for _, s := range subs {
		c := classify(s)
		buckets[c.Bucket]++
		if c.Class != "" {
			byClass[c.Class]++
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | `%s` | %s |",
			truncate(s.Title, 48), s.VulnType, orDash(c.Class), c.Bucket, s.State))
	}

	var md strings.Builder
	fmt.Fprintf(&md, "# Oracle Backfill Coverage — %d historical submissions\n\n", len(subs))
	md.WriteString("Honest reproducibility triage: which past findings the M1 success oracle could replay. No replays are faked — historical targets/creds are gone and many findings are source-code reviews.\n\n")
	md.WriteString("## Summary\n\n| bucket | count | meaning |\n|---|---|---|\n")
	fmt.Fprintf(&md, "| **%s** | %d | supported class + live HTTP target + a concrete request → reconstruct a replay_spec |\n", bucketReplayable, buckets[bucketReplayable])
	fmt.Fprintf(&md, "| %s | %d | supported class + live target, but no request in the report to rebuild a spec |\n", bucketManual, buckets[bucketManual])
	fmt.Fprintf(&md, "| %s | %d | source-code review / non-live-HTTP target — nothing to replay |\n", bucketNotHTTP, buckets[bucketNotHTTP])
	fmt.Fprintf(&md, "| %s | %d | vuln class outside the oracle v1 set |\n", bucketUnsupported, buckets[bucketUnsupported])

	md.WriteString("\n## Replayable candidates by class\n\n")
	if len(byClass) == 0 {
		md.WriteString("_none_\n")
	} else {
		classes := make([]string, 0, len(byClass))
		for k := range byClass {
			classes = append(classes, k)
		}
		sort.Strings(classes)
		md.WriteString("| class | supported-class findings |\n|---|---|\n")
		for _, c := range classes {
			fmt.Fprintf(&md, "| %s | %d |\n", c, byClass[c])
		}
	}

	md.WriteString("\n## Per-submission\n\n| title | vuln_type | oracle class | bucket | outcome |\n|---|---|---|---|---|\n")
	md.WriteString(strings.Join(rows, "\n"))
	md.WriteString("\n\n## What to do with this\n\n")
	fmt.Fprintf(&md, "- The **%d replayable candidate(s)** are where to author `replay_spec`s first and run `verify_finding` → the first real `replayed` ground-truth labels.\n", buckets[bucketReplayable])
	md.WriteString("- `needs_manual_spec` items need a human to reconstruct the request before the oracle can touch them.\n")
	md.WriteString("- `not_live_http` / `unsupported_class` define the oracle's coverage gap honestly — future oracle classes (XSS, logic) or a code-analysis verifier would be needed.\n")

	if err := os.WriteFile(out, []byte(md.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s — %d submissions: %d replayable, %d needs-manual, %d not-live-http, %d unsupported\n",
		out, len(subs), buckets[bucketReplayable], buckets[bucketManual], buckets[bucketNotHTTP], buckets[bucketUnsupported])
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "|", "/")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

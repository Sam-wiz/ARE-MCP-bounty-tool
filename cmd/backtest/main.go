// Command backtest validates the reviewer against real triager outcomes.
// For each submission that has real report content, it runs the adversarial
// panel LEAVE-ONE-OUT (excluding that finding's own lesson + RAG thread, so the
// panel can't retrieve its own answer) and compares the verdict to what the
// Bugcrowd triager actually decided.
//
// Scoring intent:
//   rejected / not-applicable  → panel SHOULD block (REJECT)   [would've saved a bad submission]
//   accepted                   → panel should NOT block (real) [must not kill money-makers]
//   duplicate                  → panel should NOT block (real; dup is about being first, not validity)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/llm"
	"github.com/samrudh/hack-ai-v2/internal/reviewer"
	"github.com/samrudh/hack-ai-v2/internal/storage"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

type message struct {
	Author string `json:"author"`
	Body   string `json:"body"`
}
type submission struct {
	SubmissionID string    `json:"submission_id"`
	Title        string    `json:"title"`
	Program      string    `json:"program"`
	Target       string    `json:"target"`
	URL          string    `json:"url"`
	VulnType     string    `json:"vuln_type"`
	Severity     string    `json:"severity"`
	State        string    `json:"state"`
	ReportBody   string    `json:"report_body"`
	Messages     []message `json:"messages"`
}

func main() {
	verbose := flag.Bool("v", false, "dump per-panelist scores + retrieved prior verdicts")
	only := flag.String("only", "", "only run findings whose title contains this substring (comma-separated)")
	flag.Parse()

	minChars := 500 // findings with less researcher content than this are title-only → skip
	config.LoadDotEnv()
	uri := os.Getenv("MONGODB_URI")
	dbName := os.Getenv("MONGODB_DATABASE")
	if dbName == "" {
		dbName = "hack_ai_v2"
	}

	raw, _ := os.ReadFile("BUGCROWD_SUBMISSIONS.md")
	var subs []submission
	if err := json.Unmarshal(raw, &subs); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	mc, err := storage.NewMongoClient(ctx, uri, dbName)
	if err != nil {
		log.Fatal(err)
	}
	defer mc.Close(ctx)

	rv := reviewer.New()
	if !rv.Available() {
		log.Fatal("no reviewer panel configured")
	}
	embedder, hasEmb := llm.EmbedderFromEnv()
	allVecs, _ := mc.AllThreadVecs(ctx)

	type result struct {
		state, verdict, title string
		correct               bool
	}
	var results []result

	for _, s := range subs {
		body := researcherBody(s)
		if len(body) < minChars || strings.EqualFold(s.State, "pending") {
			continue
		}
		if *only != "" && !matchesAny(s.Title, *only) {
			continue
		}

		in := reviewer.Input{
			Program: s.Program, Title: s.Title, Severity: s.Severity,
			VulnType: s.VulnType, Target: s.Target, URL: s.URL,
			Description: body,
		}
		// Program scope
		if p, _ := mc.GetProgram(ctx, s.Program); p != nil {
			in.ProgramScope = fmt.Sprintf("%s payout %d-%d", p.Platform, p.PayoutMin, p.PayoutMax)
		}
		// Lessons — LEAVE-ONE-OUT: drop this finding's own lesson.
		if lessons, _ := mc.GetLessons(ctx, s.Program, s.VulnType); lessons != nil {
			for _, l := range lessons {
				if l.Source == s.SubmissionID {
					continue
				}
				in.Lessons = append(in.Lessons, l.Lesson)
			}
		}
		// RAG — LEAVE-ONE-OUT: exclude this finding's own thread.
		if hasEmb && len(allVecs) > 0 {
			in.PriorVerdicts = topSimilar(ctx, embedder, allVecs, s.Title+" "+s.VulnType+" "+body, s.SubmissionID, 3)
		}

		rev, err := rv.Review(ctx, in)
		if err != nil {
			log.Printf("  %s: review error %v", short(s.Title), err)
			continue
		}
		verdict := string(rev.Verdict)
		correct := scoreCorrect(s.State, rev.Verdict)
		results = append(results, result{s.State, verdict, s.Title, correct})
		mark := "✗"
		if correct {
			mark = "✓"
		}
		fmt.Printf("%s  real=%-9s panel=%-16s  %s\n", mark, s.State, verdict, short(s.Title))

		if *verbose {
			fmt.Printf("    RAG retrieved %d prior verdict(s):\n", len(in.PriorVerdicts))
			for _, pv := range in.PriorVerdicts {
				fmt.Printf("      · %s\n", short2(pv, 150))
			}
			for _, pvd := range rev.Panel {
				if pvd.Error != "" {
					fmt.Printf("    %-28s ERROR %s\n", pvd.Model, short2(pvd.Error, 60))
					continue
				}
				flaw := ""
				if len(pvd.Flaws) > 0 {
					flaw = " | " + short2(pvd.Flaws[0], 90)
				}
				fmt.Printf("    %-28s %-16s real=%-5v impact=%-5v worth=%-5v conf=%.2f%s\n",
					pvd.Model, pvd.Verdict, pvd.IsReal, pvd.ImpactProven, pvd.WorthMoney, pvd.Confidence, flaw)
			}
			fmt.Println()
		}
	}

	// Summary
	fmt.Println("\n================ BACKTEST SUMMARY ================")
	byState := map[string][2]int{} // [correct, total]
	total, correct := 0, 0
	for _, r := range results {
		c := byState[r.state]
		c[1]++
		if r.correct {
			c[0]++
			correct++
		}
		byState[r.state] = c
		total++
	}
	for _, st := range []string{"accepted", "duplicate", "rejected"} {
		if c := byState[st]; c[1] > 0 {
			fmt.Printf("  %-10s %d/%d correct\n", st, c[0], c[1])
		}
	}
	if total > 0 {
		fmt.Printf("  OVERALL   %d/%d (%.0f%%) — panel verdict matched real outcome\n", correct, total, 100*float64(correct)/float64(total))
	}
	fmt.Printf("  (n=%d findings with real report content; %d were title-only and excluded)\n", total, len(subs)-total)
}

// scoreCorrect: rejected→should block; accepted/duplicate→should NOT block.
func scoreCorrect(state string, v types.ReviewVerdict) bool {
	blocked := v == types.VerdictReject
	switch strings.ToLower(state) {
	case "rejected", "not_applicable":
		return blocked
	case "accepted", "duplicate":
		return !blocked
	}
	return false
}

// researcherBody prefers the full original report_body; falls back to
// researcher-authored thread messages for older exports that lack it.
func researcherBody(s submission) string {
	if len(strings.TrimSpace(s.ReportBody)) >= 100 {
		return s.ReportBody
	}
	var b strings.Builder
	for _, m := range s.Messages {
		if m.Author == "researcher" && m.Body != "" && m.Body != "created the submission" {
			b.WriteString(m.Body)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func topSimilar(ctx context.Context, e llm.Embedder, vecs []storage.ThreadVec, query, excludeID string, k int) []string {
	qv, err := e.Embed(ctx, query)
	if err != nil {
		return nil
	}
	type sc struct {
		snip  string
		score float64
	}
	var ranked []sc
	for _, v := range vecs {
		if v.ID == excludeID || len(v.Embedding) == 0 || v.Snippet == "" {
			continue
		}
		ranked = append(ranked, sc{v.Snippet, llm.Cosine(qv, v.Embedding)})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })
	var out []string
	for i := 0; i < len(ranked) && i < k; i++ {
		if ranked[i].score < 0.3 {
			break
		}
		out = append(out, ranked[i].snip)
	}
	return out
}

func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 52 {
		return s[:52] + "…"
	}
	return s
}

func short2(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func matchesAny(title, csv string) bool {
	t := strings.ToLower(title)
	for _, sub := range strings.Split(csv, ",") {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub != "" && strings.Contains(t, sub) {
			return true
		}
	}
	return false
}

// Command importsubs loads a Bugcrowd submission export (JSON) into MongoDB as
// the review pipeline's real calibration data:
//
//   - triage_outcomes : one per submission → real accept-rate + reward in review_stats
//   - triage_threads  : the full verbatim researcher<->triager message threads (RLHF corpus)
//   - lessons         : auto-generated, differentiated by state:
//       rejected  → a "red-handed" corrective lesson, correlated against what the
//                   v1 hunt actually claimed (VULNERABLE vector rationale) vs the
//                   triager's reject reason
//       duplicate → a saturation lesson (valid, but not first → $0, be fresher)
//       accepted  → the pattern that pays (reinforce)
//
// Idempotent: keyed by submission_id, so re-running replaces rather than dupes.
//
//	go run ./cmd/importsubs -file BUGCROWD_SUBMISSIONS.md
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/samrudh/hack-ai-v2/internal/config"
)

type message struct {
	Author    string `json:"author"`
	Name      string `json:"name"`
	Timestamp string `json:"timestamp"`
	Body      string `json:"body"`
}

type submission struct {
	SubmissionID string    `json:"submission_id"`
	Title        string    `json:"title"`
	Program      string    `json:"program"`
	ProgramName  string    `json:"program_name"`
	Platform     string    `json:"platform"`
	Target       string    `json:"target"`
	URL          string    `json:"url"`
	VRT          string    `json:"vrt"`
	VulnType     string    `json:"vuln_type"`
	Severity     string    `json:"severity"`
	State        string    `json:"state"`
	Reward       float64   `json:"reward_amount"`
	Currency     string    `json:"currency"`
	SubmittedAt  string    `json:"submitted_at"`
	ResolvedAt   string    `json:"resolved_at"`
	DuplicateOf  string    `json:"duplicate_of"`
	RejectReason string    `json:"reject_reason"`
	ReportBody   string    `json:"report_body"`
	Messages     []message `json:"messages"`
}

// v1 archive slug aliases for correlating a submission's program to its hunt logs.
var programAliases = map[string][]string{
	"securedrop": {"securedrop", "securedrop-fpf"},
	"aiven":      {"bounty-aiven"},
	"opensea":    {"bugcrowd-opensea"},
	"auth0":      {"auth0", "auth0-cic"},
	"immutable":  {"immutable"},
	"etoro":      {"etoro", "bounty-etoro"},
	"paypal":     {"paypal-hackerone", "bounty-paypal", "paypal-mfa-bypass"},
}

func main() {
	file := flag.String("file", "BUGCROWD_SUBMISSIONS.md", "submission export JSON file")
	dry := flag.Bool("dry", false, "print what would happen without writing")
	flag.Parse()

	config.LoadDotEnv()
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatal("MONGODB_URI not set")
	}
	dbName := os.Getenv("MONGODB_DATABASE")
	if dbName == "" {
		dbName = "hack_ai_v2"
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("read %s: %v", *file, err)
	}
	var subs []submission
	if err := json.Unmarshal(raw, &subs); err != nil {
		log.Fatalf("parse json: %v", err)
	}
	log.Printf("loaded %d submissions from %s", len(subs), *file)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cl, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer cl.Disconnect(ctx)
	if err := cl.Ping(ctx, nil); err != nil {
		log.Fatalf("ping: %v", err)
	}
	db := cl.Database(dbName)
	v1 := cl.Database(dbName + "_v1")

	outcomes := db.Collection("triage_outcomes")
	threads := db.Collection("triage_threads")
	lessons := db.Collection("lessons")

	if !*dry {
		// Remove the earlier placeholder seed so real data doesn't double-count.
		if res, _ := outcomes.DeleteMany(ctx, bson.D{{Key: "notes", Value: bson.D{{Key: "$regex", Value: "Backfilled"}}}}); res != nil && res.DeletedCount > 0 {
			log.Printf("removed %d placeholder seed outcome(s)", res.DeletedCount)
		}
		// Self-heal: drop any string-_id docs from a prior buggy run. The typed
		// structs (TriageOutcome/Lesson) decode _id as ObjectID, so string _ids
		// break GetTriageOutcomes/GetLessons. We re-key on natural fields below.
		stringID := bson.D{{Key: "_id", Value: bson.D{{Key: "$type", Value: "string"}}}}
		if r, _ := outcomes.DeleteMany(ctx, stringID); r != nil && r.DeletedCount > 0 {
			log.Printf("cleaned %d string-_id outcome(s) from prior run", r.DeletedCount)
		}
		if r, _ := lessons.DeleteMany(ctx, bson.D{{Key: "source", Value: bson.D{{Key: "$exists", Value: true}}}, {Key: "_id", Value: bson.D{{Key: "$type", Value: "string"}}}}); r != nil && r.DeletedCount > 0 {
			log.Printf("cleaned %d string-_id lesson(s) from prior run", r.DeletedCount)
		}
	}

	var nOut, nThread, nLesson int
	var accepted, dup, rejected, pending int
	var reward float64

	for _, s := range subs {
		state := strings.ToUpper(strings.TrimSpace(s.State))
		switch state {
		case "ACCEPTED":
			accepted++
			reward += s.Reward
		case "DUPLICATE":
			dup++
		case "REJECTED", "NOT_APPLICABLE":
			rejected++
			state = "NOT_APPLICABLE" // map bugcrowd 'rejected' to the triage taxonomy
		case "PENDING":
			pending++
		}
		if s.Currency == "" {
			s.Currency = "USD"
		}

		// --- triage_outcome (idempotent on platform_ref; _id stays ObjectID so
		// the typed TriageOutcome struct decodes it) ---
		outDoc := bson.D{
			{Key: "finding_id", Value: ""},
			{Key: "program", Value: s.Program},
			{Key: "platform", Value: "bugcrowd"},
			{Key: "platform_ref", Value: s.SubmissionID},
			{Key: "title", Value: s.Title},
			{Key: "vuln_type", Value: s.VulnType},
			{Key: "severity", Value: s.Severity},
			{Key: "state", Value: state},
			{Key: "bugcrowd_state", Value: strings.ToLower(s.State)}, // keep the exact platform state too
			{Key: "reward_amount", Value: s.Reward},
			{Key: "currency", Value: s.Currency},
			{Key: "reject_reason", Value: s.RejectReason},
			{Key: "submitted_at", Value: parseTime(s.SubmittedAt)},
			{Key: "recorded_at", Value: time.Now()},
		}

		// --- triage_thread (full verbatim messages) ---
		threadMsgs := make([]bson.M, 0, len(s.Messages))
		for _, m := range s.Messages {
			threadMsgs = append(threadMsgs, bson.M{
				"author": m.Author, "name": m.Name,
				"timestamp": parseTime(m.Timestamp), "body": m.Body,
			})
		}
		threadDoc := bson.D{
			{Key: "_id", Value: s.SubmissionID},
			{Key: "program", Value: s.Program},
			{Key: "title", Value: s.Title},
			{Key: "vuln_type", Value: s.VulnType},
			{Key: "state", Value: strings.ToLower(s.State)},
			{Key: "report_body", Value: s.ReportBody}, // full original report, for embedding + context
			{Key: "messages", Value: threadMsgs},
			{Key: "imported_at", Value: time.Now()},
		}

		// --- lesson (differentiated by state) ---
		lessonBody, fpClass := s.buildLesson(ctx, v1)

		if *dry {
			log.Printf("[dry] %-9s %-10s %-18s $%.0f  %s", s.State, s.Program, s.VulnType, s.Reward, trunc(s.Title, 45))
			if lessonBody != "" {
				log.Printf("        lesson: %s", trunc(lessonBody, 160))
			}
			continue
		}

		// Upsert on natural keys so _id stays an ObjectID (typed-struct safe).
		upsertBy(ctx, outcomes, bson.D{{Key: "platform_ref", Value: s.SubmissionID}}, outDoc)
		nOut++
		upsert(ctx, threads, s.SubmissionID, threadDoc) // threads read raw, string _id is fine
		nThread++
		if lessonBody != "" {
			lessonDoc := bson.D{
				{Key: "program", Value: s.Program},
				{Key: "vuln_type", Value: s.VulnType},
				{Key: "fp_class", Value: fpClass},
				{Key: "lesson", Value: lessonBody},
				{Key: "source", Value: s.SubmissionID},
				{Key: "created_at", Value: time.Now()},
			}
			upsertBy(ctx, lessons, bson.D{{Key: "source", Value: s.SubmissionID}}, lessonDoc)
			nLesson++
		}
	}

	log.Printf("---")
	log.Printf("submissions: accepted=%d duplicate=%d rejected=%d pending=%d", accepted, dup, rejected, pending)
	valid := accepted + dup
	if len(subs) > 0 {
		log.Printf("accept-rate=%.0f%%  valid-rate(accepted+dup)=%.0f%%  total reward=$%.0f",
			100*float64(accepted)/float64(len(subs)), 100*float64(valid)/float64(len(subs)), reward)
	}
	if !*dry {
		log.Printf("wrote: %d outcomes, %d threads, %d lessons", nOut, nThread, nLesson)
	}
}

// buildLesson composes a state-specific lesson. For rejections it correlates the
// finding against the v1 hunt's VULNERABLE claim to catch the overclaim.
func (s submission) buildLesson(ctx context.Context, v1 *mongo.Database) (body, fpClass string) {
	switch strings.ToUpper(s.State) {
	case "ACCEPTED":
		if s.Reward > 0 {
			return fmt.Sprintf("✅ PAID $%.0f — %s/%s: %q. This is the pattern that pays: concrete, demonstrated impact with a working PoC. Do more like this.",
				s.Reward, s.Program, s.VulnType, s.Title), "paid-pattern"
		}
		return fmt.Sprintf("✅ ACCEPTED (no bounty, %s) — %s/%s: %q. Valid and in-scope but low payoff. Fine to file, don't over-invest.",
			s.Severity, s.Program, s.VulnType, s.Title), "accepted-lowvalue"

	case "DUPLICATE":
		return fmt.Sprintf("♻️ DUPLICATE (valid but not first) — %s/%s: %q. The finding was CORRECT but already reported; this surface is saturated. To earn on %s, hit fresh scope or move faster — expect $0 on known classes here.",
			s.Program, s.VulnType, s.Title, s.Program), "duplicate-saturated"

	case "REJECTED":
		gist := stripBoilerplate(s.RejectReason)
		claim, found := correlateOverclaim(ctx, v1, s)
		if found {
			return fmt.Sprintf("❌ REJECTED — %s/%s: %q. Triager closed it: %q. The engine had marked this VULNERABLE claiming: %q. Marking a code path 'CONFIRMED/LIVE' in a test harness is NOT a triager-grade PoC. Before submitting this class, produce a reproducing exploit that demonstrates the security CONSEQUENCE on a real deployment — not just that the code executes.",
				s.Program, s.VulnType, s.Title, trunc(gist, 220), trunc(claim, 200)), "rejected-overclaim:" + s.VulnType
		}
		return fmt.Sprintf("❌ REJECTED — %s/%s: %q. Triager: %q. Don't resubmit this pattern without demonstrated, exploited security impact (a working PoC showing real consequence, not theory).",
			s.Program, s.VulnType, s.Title, trunc(gist, 220)), "rejected:" + s.VulnType
	}
	return "", ""
}

// correlateOverclaim finds the v1 VULNERABLE vector whose rationale best matches
// this rejected finding, returning its (overclaiming) rationale.
func correlateOverclaim(ctx context.Context, v1 *mongo.Database, s submission) (string, bool) {
	slugs := programAliases[s.Program]
	if len(slugs) == 0 {
		slugs = []string{s.Program}
	}
	cur, err := v1.Collection("vector_statuses").Find(ctx, bson.D{
		{Key: "program", Value: bson.D{{Key: "$in", Value: slugs}}},
		{Key: "state", Value: "VULNERABLE"},
	})
	if err != nil {
		return "", false
	}
	defer cur.Close(ctx)

	toks := tokens(s.VulnType + " " + s.Title)
	best := ""
	bestScore := 0
	for cur.Next(ctx) {
		var vs struct {
			VectorID  string `bson:"vector_id"`
			Rationale string `bson:"rationale"`
		}
		if cur.Decode(&vs) != nil {
			continue
		}
		hay := strings.ToLower(vs.VectorID + " " + vs.Rationale)
		score := 0
		for t := range toks {
			if strings.Contains(hay, t) {
				score++
			}
		}
		// Strong preference for rationales that assert confidence (the overclaim).
		if strings.Contains(hay, "confirm") {
			score += 2
		}
		if score > bestScore {
			bestScore = score
			best = vs.Rationale
		}
	}
	return best, bestScore >= 2 && best != ""
}

var wordRe = regexp.MustCompile(`[a-z0-9]{4,}`)

// tokens returns significant lowercase tokens, dropping common filler.
func tokens(s string) map[string]bool {
	stop := map[string]bool{"before": true, "after": true, "with": true, "that": true, "this": true,
		"from": true, "into": true, "user": true, "auth": true, "check": true, "over": true, "vuln": true}
	out := map[string]bool{}
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if !stop[w] {
			out[w] = true
		}
	}
	return out
}

var boilerRe = regexp.MustCompile(`(?i)(hi sam-wiz,|your effort is appreciated.*?submissions\.|best regards,|- \w+-?\w*$)`)

// stripBoilerplate removes the standard greeting/closing, leaving the triager's
// substantive complaint (the actual signal).
func stripBoilerplate(reason string) string {
	r := boilerRe.ReplaceAllString(reason, "")
	r = regexp.MustCompile(`(?i)we believe this issue to be a false-positive and as such,? are closing this report\.?`).ReplaceAllString(r, "")
	r = regexp.MustCompile(`(?i)if you still believe.*?report\.?`).ReplaceAllString(r, "")
	r = strings.Join(strings.Fields(r), " ")
	if r == "" {
		return strings.Join(strings.Fields(reason), " ")
	}
	return r
}

func upsert(ctx context.Context, coll *mongo.Collection, id interface{}, doc bson.D) {
	_, err := coll.ReplaceOne(ctx, bson.D{{Key: "_id", Value: id}}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		log.Printf("  upsert %v failed: %v", id, err)
	}
}

// upsertBy replaces the doc matching filter (or inserts it), leaving _id to be a
// Mongo-generated ObjectID so typed structs can decode it.
func upsertBy(ctx context.Context, coll *mongo.Collection, filter, doc bson.D) {
	_, err := coll.ReplaceOne(ctx, filter, doc, options.Replace().SetUpsert(true))
	if err != nil {
		log.Printf("  upsert %v failed: %v", filter, err)
	}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Command migrate imports the v1 mongo-export JSON snapshot into the new
// (v2) cluster under "<collection>_v1" collections, leaving the fresh
// collections empty for the running engine to write to. It also seeds the
// v2 review-pipeline collections (the real Auth0 payout + baseline lessons).
//
// Usage:
//
//	go run ./cmd/migrate            # import + seed (skips collections that already have data)
//	go run ./cmd/migrate -force     # drop existing *_v1 collections and re-import
//	go run ./cmd/migrate -src DIR   # import from a different export dir
//
// The MongoDB URI is read from .env (MONGODB_URI) and never printed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/samrudh/hack-ai-v2/internal/config"
)

// v1 collections present in the export.
var v1Collections = []string{
	"decisions", "findings", "programs", "script_executions",
	"sessions", "tool_runs", "vector_statuses", "consultations",
}

func main() {
	src := flag.String("src", "mongo-export/latest", "directory containing the v1 JSON export")
	force := flag.Bool("force", false, "drop existing *_v1 collections and re-import")
	flag.Parse()

	config.LoadDotEnv()
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatal("MONGODB_URI is not set (put it in .env)")
	}
	dbName := os.Getenv("MONGODB_DATABASE")
	if dbName == "" {
		dbName = "hack_ai_v2"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer client.Disconnect(ctx)
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("ping failed: %v", err)
	}
	db := client.Database(dbName)
	archiveDB := client.Database(dbName + "_v1") // v1 archive lives in its own database
	log.Printf("Connected. Main DB: %q   v1 archive DB: %q", dbName, dbName+"_v1")

	// --- Import v1 collections into the archive DB under their original names ---
	for _, name := range v1Collections {
		path := filepath.Join(*src, name+".json")
		if _, err := os.Stat(path); err != nil {
			log.Printf("skip %-18s (no export file)", name)
			continue
		}
		coll := archiveDB.Collection(name)

		count, _ := coll.CountDocuments(ctx, bson.D{})
		if count > 0 {
			if !*force {
				log.Printf("skip %-18s → %s.%s already has %d docs (use -force to replace)", name, dbName+"_v1", name, count)
				continue
			}
			if err := coll.Drop(ctx); err != nil {
				log.Printf("warn: could not drop %s: %v", name, err)
			}
		}

		n, err := importFile(ctx, coll, path)
		if err != nil {
			log.Printf("ERROR importing %s: %v", name, err)
			continue
		}
		log.Printf("imported %-18s → %s.%s (%d docs)", name, dbName+"_v1", name, n)
	}

	// --- Seed v2 review-pipeline collections (in the MAIN db) ---
	seedOutcomes(ctx, db)
	seedLessons(ctx, db)

	log.Printf("Migration complete. v1 archive is in database %q; main DB %q holds only live + v2 collections.", dbName+"_v1", dbName)
}

// importFile parses an extended-JSON array and bulk-inserts it.
func importFile(ctx context.Context, coll *mongo.Collection, path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return 0, fmt.Errorf("parse array: %w", err)
	}

	const batch = 1000
	total := 0
	docs := make([]interface{}, 0, batch)
	flush := func() error {
		if len(docs) == 0 {
			return nil
		}
		if _, err := coll.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false)); err != nil {
			return err
		}
		total += len(docs)
		docs = docs[:0]
		return nil
	}

	for _, el := range elems {
		var doc bson.D
		if err := bson.UnmarshalExtJSON(el, false, &doc); err != nil {
			// skip a single malformed doc rather than abort the whole import
			log.Printf("  warn: skipping malformed doc in %s: %v", filepath.Base(path), err)
			continue
		}
		docs = append(docs, doc)
		if len(docs) >= batch {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := flush(); err != nil {
		return total, err
	}
	return total, nil
}

// seedOutcomes records the one real datapoint v1 never logged: the Auth0 payout.
func seedOutcomes(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("triage_outcomes")
	if n, _ := coll.CountDocuments(ctx, bson.D{}); n > 0 {
		log.Printf("skip seed triage_outcomes (already has %d docs)", n)
		return
	}
	_, err := coll.InsertOne(ctx, bson.D{
		{Key: "finding_id", Value: ""},
		{Key: "program", Value: "auth0"},
		{Key: "platform", Value: "bugcrowd"},
		{Key: "platform_ref", Value: ""},
		{Key: "title", Value: "Auth0 finding (backfilled — the one real v1 payout)"},
		{Key: "vuln_type", Value: ""},
		{Key: "severity", Value: ""},
		{Key: "state", Value: "ACCEPTED"},
		{Key: "reward_amount", Value: 1100.0},
		{Key: "currency", Value: "USD"},
		{Key: "notes", Value: "Backfilled: the only finding that actually paid in v1 was never logged. Update finding_id/vuln_type when known."},
		{Key: "recorded_at", Value: time.Now()},
	})
	if err != nil {
		log.Printf("warn: seed outcome failed: %v", err)
		return
	}
	log.Println("seeded triage_outcomes with the real Auth0 $1,100 payout")
}

// seedLessons plants baseline false-positive-class grounding for the reviewer.
func seedLessons(ctx context.Context, db *mongo.Database) {
	coll := db.Collection("lessons")
	if n, _ := coll.CountDocuments(ctx, bson.D{}); n > 0 {
		log.Printf("skip seed lessons (already has %d docs)", n)
		return
	}
	now := time.Now()
	lessons := []bson.D{
		{{Key: "fp_class", Value: "public-client-key"}, {Key: "lesson", Value: "Braintree/Stripe tokenization & publishable keys, Alchemy/Infura app keys, Google Maps keys, and any NEXT_PUBLIC_*/VITE_*/REACT_APP_* value are public by design. Presence in a JS bundle is NOT a leak unless privileged use is demonstrated."}, {Key: "source", Value: "v1-postmortem"}, {Key: "created_at", Value: now}},
		{{Key: "fp_class", Value: "unexploited-cors"}, {Key: "lesson", Value: "A CORS origin-reflection / ACAC header is not a vulnerability until a cross-origin read of authenticated, sensitive data is demonstrated end-to-end. Header presence alone is informational."}, {Key: "source", Value: "v1-postmortem"}, {Key: "created_at", Value: now}},
		{{Key: "fp_class", Value: "spec-nitpick"}, {Key: "lesson", Value: "OIDC discovery listing signing algorithms (RS256/ES256) as PKCE methods, missing security headers, verbose errors, and version disclosure are almost always closed Informational. Don't submit as standalone bugs."}, {Key: "source", Value: "v1-postmortem"}, {Key: "created_at", Value: now}},
		{{Key: "fp_class", Value: "indicator-not-impact"}, {Key: "lesson", Value: "A status-code difference, a config value, or a reachable admin path is an indicator, not proven impact. Chain it to a concrete, demonstrated consequence before claiming a finding."}, {Key: "source", Value: "v1-postmortem"}, {Key: "created_at", Value: now}},
		{{Key: "program", Value: "kickbacks-ai"}, {Key: "lesson", Value: "kickbacks-ai has a $0 bounty range. Findings here (however real) do not pay — deprioritise report-writing effort accordingly."}, {Key: "source", Value: "v1-postmortem"}, {Key: "created_at", Value: now}},
	}
	docs := make([]interface{}, len(lessons))
	for i, l := range lessons {
		docs[i] = l
	}
	if _, err := coll.InsertMany(ctx, docs); err != nil {
		log.Printf("warn: seed lessons failed: %v", err)
		return
	}
	log.Printf("seeded lessons with %d baseline false-positive classes", len(lessons))
}

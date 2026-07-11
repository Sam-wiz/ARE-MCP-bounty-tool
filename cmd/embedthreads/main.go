// Command embedthreads computes an embedding for each triage_thread that lacks
// one, so review_report can retrieve semantically-similar past triager verdicts.
// Lightweight: embeddings are stored inline on the thread doc and searched with
// brute-force cosine at review time (no vector DB).
//
//	go run ./cmd/embedthreads          # embed threads missing an embedding
//	go run ./cmd/embedthreads -reembed # re-embed everything
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/samrudh/hack-ai-v2/internal/config"
	"github.com/samrudh/hack-ai-v2/internal/llm"
	"github.com/samrudh/hack-ai-v2/internal/storage"
)

func main() {
	reembed := flag.Bool("reembed", false, "re-embed all threads (clears existing embeddings first)")
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

	embedder, ok := llm.EmbedderFromEnv()
	if !ok {
		log.Fatal("no embedder configured (set OPENAI_API_KEY, or EMBED_PROVIDER=nvidia + NVIDIA_API_KEY)")
	}
	log.Printf("embedder: %s", embedder.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	mc, err := storage.NewMongoClient(ctx, uri, dbName)
	if err != nil {
		log.Fatalf("mongo: %v", err)
	}
	defer mc.Close(ctx)

	if *reembed {
		mc.ClearThreadEmbeddings(ctx)
	}

	docs, err := mc.GetThreadsForEmbedding(ctx)
	if err != nil {
		log.Fatalf("fetch threads: %v", err)
	}
	log.Printf("%d threads to embed", len(docs))

	n := 0
	for _, d := range docs {
		id, _ := d["_id"].(string)
		text, snippet := buildTextAndSnippet(d)
		if strings.TrimSpace(text) == "" {
			continue
		}
		vec, err := embedder.Embed(ctx, text)
		if err != nil {
			log.Printf("  embed %s: %v", id, err)
			continue
		}
		if err := mc.SetThreadEmbedding(ctx, id, snippet, vec); err != nil {
			log.Printf("  store %s: %v", id, err)
			continue
		}
		n++
	}
	log.Printf("embedded %d threads (dim=%s)", n, dimNote(docs))
}

// buildTextAndSnippet derives:
//   text    — what to EMBED: the finding's own content (title + report body), so
//             a new finding matches past findings by content similarity.
//   snippet — what to INJECT at review time: the compact triager verdict, i.e.
//             "here's how a triager ruled on a finding like yours".
func buildTextAndSnippet(d bson.M) (text, snippet string) {
	title, _ := d["title"].(string)
	program, _ := d["program"].(string)
	state, _ := d["state"].(string)
	report, _ := d["report_body"].(string)
	report = strings.Join(strings.Fields(report), " ")

	var triagerBits []string
	if msgs, ok := d["messages"].(bson.A); ok {
		for _, mm := range msgs {
			msg, ok := mm.(bson.M)
			if !ok {
				continue
			}
			author, _ := msg["author"].(string)
			body, _ := msg["body"].(string)
			body = strings.Join(strings.Fields(body), " ")
			if author == "triager" && len(body) > 25 { // substantive triager verdict text
				triagerBits = append(triagerBits, body)
			}
		}
	}
	reason := strings.Join(triagerBits, " ")

	// Embed the finding content; fall back to title+reason if no report body.
	text = title + ". " + report
	if len(strings.TrimSpace(report)) < 30 {
		text = title + ". Triager: " + reason
	}

	gist := reason
	if len(gist) > 220 {
		gist = gist[:220] + "…"
	}
	snippet = fmt.Sprintf("[%s · %s] %s — triager ruled: %s", program, strings.ToUpper(state), trunc(title, 90), gist)
	return text, snippet
}

func dimNote(docs []bson.M) string {
	if len(docs) == 0 {
		return "n/a"
	}
	return "ok"
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

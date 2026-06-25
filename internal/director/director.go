// Package director extends the engine's horizon when it gets stuck. It asks a
// strong model to propose NEW, untried attack hypotheses — deliberately kept
// separate from the reviewer so neither job dilutes the other.
//
// Two guardrails from the design discussion:
//   - It is fed the already-explored vectors (EXHAUSTED / BLOCKED / VULNERABLE)
//     and must not re-propose them; re-treading dead ground burns the engine's
//     limited horizon.
//   - Its output is HYPOTHESES to test, never findings. Everything it proposes
//     still has to pass the confirmation gate, so it cannot inject false
//     positives directly into a report.
package director

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samrudh/hack-ai-v2/internal/llm"
	"github.com/samrudh/hack-ai-v2/internal/types"
)

// Director wraps the strong brainstorming model.
type Director struct {
	Model llm.Provider
	ok    bool
}

// New builds a Director from environment configuration.
func New() *Director {
	p, ok := llm.DirectorFromEnv()
	return &Director{Model: p, ok: ok}
}

// Available reports whether a director model is configured.
func (d *Director) Available() bool { return d.ok }

// ModelName returns the configured director model label.
func (d *Director) ModelName() string { return d.Model.Name }

// Input describes the stuck state the director should break out of.
type Input struct {
	Program    string
	Scope      string
	Exhausted  []string // vector ids already driven to a dead end
	Blocked    []string // vector ids blocked by design / WAF / auth
	Vulnerable []string // vector ids already confirmed (don't rehash)
	Notes      string   // free-text: what was tried, why stuck
	Max        int      // max hypotheses to return (default 6)
}

const systemPrompt = `You are the Director: a principal offensive-security researcher guiding an automated bug-bounty engine that has run out of ideas on a target. Propose NEW, concrete, high-expected-value attack hypotheses the engine has NOT already tried.

Hard rules:
- Do NOT repeat any vector in the "already explored" lists (exhausted, blocked, or already-confirmed). Propose genuinely new surface.
- Prefer vectors with direct impact (auth bypass, IDOR/BOLA, cross-tenant access, fund loss, RCE, SSRF-to-internal) over low-value noise (missing headers, verbose errors, self-XSS).
- Each hypothesis is something to TEST, not a claimed finding. Be specific about how to test it.
- Respect scope. Do not propose out-of-scope targets.

Reply with ONLY a JSON object of this shape:
{
  "hypotheses": [
    {
      "vector_id": "SHORT-CANONICAL-ID",      // stable id, e.g. "IDOR-/api/v2/orders/{id}"
      "title": "one-line description",
      "rationale": "why this is plausible and high value here",
      "how_to_test": "concrete steps / requests to run",
      "priority": "high" | "medium" | "low"
    }
  ]
}`

// Horizon asks the director for new hypotheses, filtering out anything that
// collides with an already-explored vector id.
func (d *Director) Horizon(ctx context.Context, in Input) ([]types.Hypothesis, error) {
	if !d.ok {
		return nil, fmt.Errorf("no director model configured — set DIRECTOR_PROVIDER/DIRECTOR_MODEL (and the matching API key) in .env")
	}
	if in.Max <= 0 {
		in.Max = 6
	}

	raw, err := d.Model.Chat(ctx, systemPrompt, buildPrompt(in), true)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Hypotheses []struct {
			VectorID   string `json:"vector_id"`
			Title      string `json:"title"`
			Rationale  string `json:"rationale"`
			HowToTest  string `json:"how_to_test"`
			Priority   string `json:"priority"`
		} `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(raw)), &parsed); err != nil {
		return nil, fmt.Errorf("director returned unparseable JSON: %w", err)
	}

	// Build the exclusion set (case/space-insensitive).
	explored := map[string]bool{}
	for _, list := range [][]string{in.Exhausted, in.Blocked, in.Vulnerable} {
		for _, v := range list {
			explored[normID(v)] = true
		}
	}

	var out []types.Hypothesis
	for _, h := range parsed.Hypotheses {
		if h.VectorID == "" || explored[normID(h.VectorID)] {
			continue // skip empty or already-explored
		}
		out = append(out, types.Hypothesis{
			Program:   in.Program,
			VectorID:  h.VectorID,
			Title:     h.Title,
			Rationale: h.Rationale,
			HowToTest: h.HowToTest,
			Priority:  strings.ToLower(strings.TrimSpace(h.Priority)),
		})
		if len(out) >= in.Max {
			break
		}
	}
	return out, nil
}

func normID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func buildPrompt(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target program: %s\n\n", in.Program)
	if in.Scope != "" {
		fmt.Fprintf(&b, "Scope & rules:\n%s\n\n", in.Scope)
	}
	writeList(&b, "Already EXHAUSTED (dead ends, do not repeat)", in.Exhausted)
	writeList(&b, "Already BLOCKED (do not repeat)", in.Blocked)
	writeList(&b, "Already CONFIRMED vulnerable (do not rehash)", in.Vulnerable)
	if in.Notes != "" {
		fmt.Fprintf(&b, "\nContext on what was tried and why the engine is stuck:\n%s\n", in.Notes)
	}
	fmt.Fprintf(&b, "\nPropose up to %d NEW hypotheses. Return ONLY the JSON object.", in.Max)
	return b.String()
}

func writeList(b *strings.Builder, header string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n", header)
	for _, it := range items {
		fmt.Fprintf(b, "- %s\n", it)
	}
	b.WriteString("\n")
}

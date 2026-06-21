// Package llm provides thin OpenAI-compatible chat clients used to assemble the
// reviewer panel and the director. Every provider (OpenAI, NVIDIA NIM, ...)
// speaks the same /chat/completions schema, so a single client covers all of
// them; a "panel" is just a slice of providers pointed at different models.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Provider is one addressable model behind an OpenAI-compatible endpoint.
type Provider struct {
	Name    string // human label, e.g. "openai:gpt-4.5-preview"
	BaseURL string // e.g. https://api.openai.com/v1
	APIKey  string
	Model   string
	client  *http.Client
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	Temperature    float64         `json:"temperature"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"` // "json_object"
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat sends a system+user prompt and returns the assistant text. When jsonMode
// is true it requests a JSON object response (supported by OpenAI and NIM).
func (p Provider) Chat(ctx context.Context, system, user string, jsonMode bool) (string, error) {
	reqBody := chatRequest{
		Model:       p.Model,
		Temperature: 0.2, // reviewers should be steady, not creative
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	}
	if jsonMode {
		reqBody.ResponseFormat = &responseFormat{Type: "json_object"}
	}

	buf, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	url := strings.TrimRight(p.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)

	client := p.client
	if client == nil {
		client = defaultHTTPClient()
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned %d: %s", p.Name, resp.StatusCode, truncate(string(body), 300))
	}

	var cr chatResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return "", fmt.Errorf("%s: bad response json: %w", p.Name, err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("%s: %s", p.Name, cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("%s: no choices in response", p.Name)
	}
	return cr.Choices[0].Message.Content, nil
}

func defaultHTTPClient() *http.Client {
	secs := 120
	if v := os.Getenv("REVIEW_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			secs = n
		}
	}
	return &http.Client{Timeout: time.Duration(secs) * time.Second}
}

// PanelFromEnv assembles the reviewer panel from environment configuration:
//   - OpenAI (OPENAI_API_KEY, OPENAI_REVIEW_MODEL)
//   - one NVIDIA panelist per model in NVIDIA_REVIEW_MODELS (NVIDIA_API_KEY)
//
// Missing keys are simply skipped, so the panel scales with what's configured.
func PanelFromEnv() []Provider {
	var panel []Provider
	httpClient := defaultHTTPClient()

	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		base := envOr("OPENAI_BASE_URL", "https://api.openai.com/v1")
		// Support a reliable multi-model OpenAI core via OPENAI_REVIEW_MODELS
		// (comma-separated); fall back to the single OPENAI_REVIEW_MODEL. This
		// keeps the panel ≥2 models even when NVIDIA's serverless tier is down.
		models := splitCSV(os.Getenv("OPENAI_REVIEW_MODELS"))
		if len(models) == 0 {
			models = []string{envOr("OPENAI_REVIEW_MODEL", "gpt-4.1")}
		}
		for _, model := range models {
			panel = append(panel, Provider{
				Name:    "openai:" + model,
				BaseURL: base,
				APIKey:  key,
				Model:   model,
				client:  httpClient,
			})
		}
	}

	if key := os.Getenv("NVIDIA_API_KEY"); key != "" {
		base := envOr("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
		for _, model := range splitCSV(os.Getenv("NVIDIA_REVIEW_MODELS")) {
			panel = append(panel, Provider{
				Name:    "nvidia:" + model,
				BaseURL: base,
				APIKey:  key,
				Model:   model,
				client:  httpClient,
			})
		}
	}

	return panel
}

// DirectorFromEnv returns the strong model used for brainstorming new horizons.
// Falls back to the first panelist if DIRECTOR_* is unset. ok is false when no
// provider at all is configured.
func DirectorFromEnv() (Provider, bool) {
	provider := strings.ToLower(envOr("DIRECTOR_PROVIDER", "openai"))
	model := os.Getenv("DIRECTOR_MODEL")
	httpClient := defaultHTTPClient()

	switch provider {
	case "openai":
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			if model == "" {
				model = envOr("OPENAI_REVIEW_MODEL", "gpt-4.5-preview")
			}
			return Provider{
				Name:    "openai:" + model,
				BaseURL: envOr("OPENAI_BASE_URL", "https://api.openai.com/v1"),
				APIKey:  key, Model: model, client: httpClient,
			}, true
		}
	case "nvidia":
		if key := os.Getenv("NVIDIA_API_KEY"); key != "" {
			if model == "" {
				model = firstCSV(os.Getenv("NVIDIA_REVIEW_MODELS"))
			}
			if model != "" {
				return Provider{
					Name:    "nvidia:" + model,
					BaseURL: envOr("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
					APIKey:  key, Model: model, client: httpClient,
				}, true
			}
		}
	}

	// Fallback: first configured panelist.
	if panel := PanelFromEnv(); len(panel) > 0 {
		return panel[0], true
	}
	return Provider{}, false
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstCSV(s string) string {
	if parts := splitCSV(s); len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ExtractJSON pulls the first balanced JSON object out of a model response,
// tolerating markdown code fences and prose the model wraps around it.
func ExtractJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return s
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return s[start:]
}

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
	// Shape selects the wire format: "" or "openai" (default, /chat/completions)
	// or "anthropic" (Claude /messages format, used by e.g. Factory's Claude
	// gateway at /api/llm/a/v1/messages).
	Shape string
	// Headers are extra static headers sent with every request (e.g.
	// x-api-provider: fireworks for Factory's open-model gateway).
	Headers map[string]string
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
	if p.Shape == "anthropic" {
		return p.chatAnthropic(ctx, system, user)
	}
	return p.chatOpenAI(ctx, system, user, jsonMode)
}

// applyHeaders sets the standard auth/content headers plus any extra static
// headers configured on the provider.
func (p Provider) applyHeaders(httpReq *http.Request) {
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	for k, v := range p.Headers {
		httpReq.Header.Set(k, v)
	}
}

func (p Provider) do(ctx context.Context, url string, buf []byte) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	p.applyHeaders(httpReq)

	client := p.client
	if client == nil {
		client = defaultHTTPClient()
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %s", p.Name, resp.StatusCode, truncate(string(body), 300))
	}
	return body, nil
}

func (p Provider) chatOpenAI(ctx context.Context, system, user string, jsonMode bool) (string, error) {
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
	body, err := p.do(ctx, url, buf)
	if err != nil {
		return "", err
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

// Anthropic /messages wire format (Claude gateways, e.g. Factory
// /api/llm/a/v1/messages). No response_format knob; reviewers get JSON by
// prompt contract instead.
type anthropicRequest struct {
	Model       string        `json:"model"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature,omitempty"`
	System      string        `json:"system,omitempty"`
	Messages    []chatMessage `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p Provider) chatAnthropic(ctx context.Context, system, user string) (string, error) {
	reqBody := anthropicRequest{
		Model:       p.Model,
		MaxTokens:   8192,
		Temperature: 0.2,
		System:      system,
		Messages:    []chatMessage{{Role: "user", Content: user}},
	}

	buf, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	// BaseURL may point at .../v1 or directly at .../v1/messages.
	url := strings.TrimRight(p.BaseURL, "/")
	if !strings.HasSuffix(url, "/messages") {
		url += "/messages"
	}
	body, err := p.do(ctx, url, buf)
	if err != nil {
		return "", err
	}

	var ar anthropicResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return "", fmt.Errorf("%s: bad response json: %w", p.Name, err)
	}
	if ar.Error != nil {
		return "", fmt.Errorf("%s: %s", p.Name, ar.Error.Message)
	}
	var sb strings.Builder
	for _, block := range ar.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("%s: no text content in response", p.Name)
	}
	return sb.String(), nil
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
//   - OpenAI (OPENAI_API_KEY, OPENAI_REVIEW_MODEL) — set OPENAI_REVIEW_MODELS=off
//     to disable without removing the key (it may power other tools)
//   - one NVIDIA panelist per model in NVIDIA_REVIEW_MODELS (NVIDIA_API_KEY) —
//     NVIDIA_REVIEW_MODELS=off disables likewise
//   - generic numbered slots PANEL_1_* ... PANEL_8_* for any OpenAI- or
//     Anthropic-compatible gateway:
//     PANEL_N_NAME         label prefix (default "panelN")
//     PANEL_N_BASE_URL     required to activate the slot
//     PANEL_N_API_KEY      literal key, or
//     PANEL_N_API_KEY_ENV  name of the env var holding the key
//     PANEL_N_MODELS       comma-separated model IDs
//     PANEL_N_SHAPE        "openai" (default) or "anthropic"
//     PANEL_N_HEADERS      semicolon-separated "Key:Value" pairs
//
// Missing keys are simply skipped, so the panel scales with what's configured.
func PanelFromEnv() []Provider {
	var panel []Provider
	httpClient := defaultHTTPClient()

	if key := os.Getenv("OPENAI_API_KEY"); key != "" && !isOff(os.Getenv("OPENAI_REVIEW_MODELS")) {
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

	if key := os.Getenv("NVIDIA_API_KEY"); key != "" && !isOff(os.Getenv("NVIDIA_REVIEW_MODELS")) {
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

	for i := 1; i <= 8; i++ {
		prefix := fmt.Sprintf("PANEL_%d_", i)
		base := os.Getenv(prefix + "BASE_URL")
		if base == "" {
			continue
		}
		key := os.Getenv(prefix + "API_KEY")
		if key == "" {
			if envName := os.Getenv(prefix + "API_KEY_ENV"); envName != "" {
				key = os.Getenv(envName)
			}
		}
		if key == "" {
			continue // slot configured but no credential yet
		}
		models := splitCSV(os.Getenv(prefix + "MODELS"))
		if len(models) == 0 || isOff(os.Getenv(prefix+"MODELS")) {
			continue
		}
		label := envOr(prefix+"NAME", fmt.Sprintf("panel%d", i))
		shape := strings.ToLower(envOr(prefix+"SHAPE", "openai"))
		headers := parseHeaders(os.Getenv(prefix + "HEADERS"))
		for _, model := range models {
			panel = append(panel, Provider{
				Name:    label + ":" + model,
				BaseURL: base,
				APIKey:  key,
				Model:   model,
				Shape:   shape,
				Headers: headers,
				client:  httpClient,
			})
		}
	}

	return panel
}

// isOff reports whether a model list was explicitly disabled ("off" or "-").
func isOff(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "off" || v == "-"
}

// parseHeaders parses semicolon-separated "Key:Value" pairs.
func parseHeaders(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(pair, ":")
		if ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
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

	// Generic panel slots: DIRECTOR_PROVIDER matches a slot label (the part
	// before ":"), DIRECTOR_MODEL optionally picks the model within it.
	if panel := PanelFromEnv(); len(panel) > 0 {
		for _, p := range panel {
			label, _, _ := strings.Cut(p.Name, ":")
			if label == provider && (model == "" || p.Model == model) {
				return p, true
			}
		}
		// Fallback: first configured panelist.
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

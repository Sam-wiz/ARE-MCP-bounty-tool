package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
)

// Embedder produces vector embeddings via an OpenAI-compatible /embeddings
// endpoint. Kept intentionally small — used for lightweight semantic retrieval
// over past triager verdicts (brute-force cosine, no vector DB).
type Embedder struct {
	Name    string
	BaseURL string
	APIKey  string
	Model   string
	client  *http.Client
}

// EmbedderFromEnv builds an embedder from EMBED_* env, falling back to the
// OpenAI reviewer key. Returns ok=false when nothing is configured — callers
// then simply skip retrieval (it's an optional enrichment, never required).
func EmbedderFromEnv() (Embedder, bool) {
	provider := strings.ToLower(envOr("EMBED_PROVIDER", "openai"))
	model := os.Getenv("EMBED_MODEL")

	switch provider {
	case "nvidia":
		if key := os.Getenv("NVIDIA_API_KEY"); key != "" {
			if model == "" {
				model = "nvidia/llama-3.2-nv-embedqa-1b-v1"
			}
			return Embedder{Name: "nvidia:" + model, BaseURL: envOr("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
				APIKey: key, Model: model, client: defaultHTTPClient()}, true
		}
	default: // openai
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			if model == "" {
				model = "text-embedding-3-small"
			}
			return Embedder{Name: "openai:" + model, BaseURL: envOr("OPENAI_BASE_URL", "https://api.openai.com/v1"),
				APIKey: key, Model: model, client: defaultHTTPClient()}, true
		}
	}
	return Embedder{}, false
}

type embedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Embed returns the embedding vector for a single text.
func (e Embedder) Embed(ctx context.Context, text string) ([]float32, error) {
	body, _ := json.Marshal(map[string]interface{}{"model": e.Model, "input": text})
	url := strings.TrimRight(e.BaseURL, "/") + "/embeddings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.APIKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s embeddings %d: %s", e.Name, resp.StatusCode, truncate(string(raw), 200))
	}
	var er embedResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return nil, err
	}
	if er.Error != nil {
		return nil, fmt.Errorf("%s: %s", e.Name, er.Error.Message)
	}
	if len(er.Data) == 0 {
		return nil, fmt.Errorf("%s: empty embedding response", e.Name)
	}
	return er.Data[0].Embedding, nil
}

// Cosine returns cosine similarity of two equal-length vectors (0 if mismatched).
func Cosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

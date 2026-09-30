package oracle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPCallbackOOB is a self-hosted out-of-band catcher: it listens on a local
// port and records the first hit per token. NewToken hands out a unique URL
// (baseURL/<token>); when a target dereferences it (SSRF), Poll sees the hit.
//
// This is a real, dependency-free OOB primitive suitable when the target can
// reach the engine's host (common for internal SSRF). For public/egress-blind
// SSRF, swap in an interactsh-backed OOBClient with the same interface — the
// oracle doesn't care which implementation it gets.
type HTTPCallbackOOB struct {
	baseURL string
	ln      net.Listener
	server  *http.Server
	mu      sync.Mutex
	hits    map[string]string // token -> first-hit detail
}

// NewHTTPCallbackOOB starts the catcher. listenAddr is where it binds (e.g.
// "0.0.0.0:8899" or ":0" for an ephemeral port). baseURL is the URL a target
// would use to reach it (e.g. "http://10.0.0.5:8899"); if empty it's derived
// from the bound address (fine for local/loopback testing).
func NewHTTPCallbackOOB(listenAddr, baseURL string) (*HTTPCallbackOOB, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("oob listen %s: %w", listenAddr, err)
	}
	o := &HTTPCallbackOOB{
		baseURL: strings.TrimRight(baseURL, "/"),
		ln:      ln,
		hits:    map[string]string{},
	}
	if o.baseURL == "" {
		o.baseURL = "http://" + ln.Addr().String()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", o.handle)
	o.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go o.server.Serve(ln)
	return o, nil
}

func (o *HTTPCallbackOOB) handle(w http.ResponseWriter, r *http.Request) {
	token := firstPathSegment(r.URL.Path)
	if token != "" {
		o.mu.Lock()
		if _, seen := o.hits[token]; !seen {
			o.hits[token] = fmt.Sprintf("%s %s from %s at %s", r.Method, r.URL.Path, r.RemoteAddr, time.Now().UTC().Format(time.RFC3339))
		}
		o.mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// NewToken returns a unique token and the full URL a target should hit.
func (o *HTTPCallbackOOB) NewToken(_ context.Context) (token, host string, err error) {
	token = randToken(10)
	return token, o.baseURL + "/" + token, nil
}

// Poll blocks until the token is hit or the window elapses.
func (o *HTTPCallbackOOB) Poll(ctx context.Context, token string, within time.Duration) (bool, string, error) {
	deadline := time.Now().Add(within)
	for {
		o.mu.Lock()
		detail, ok := o.hits[token]
		o.mu.Unlock()
		if ok {
			return true, detail, nil
		}
		if time.Now().After(deadline) {
			return false, "", nil
		}
		select {
		case <-ctx.Done():
			return false, "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// BaseURL is the URL targets reach this catcher on.
func (o *HTTPCallbackOOB) BaseURL() string { return o.baseURL }

// Close stops the listener.
func (o *HTTPCallbackOOB) Close() error { return o.server.Close() }

func firstPathSegment(p string) string {
	p = strings.Trim(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

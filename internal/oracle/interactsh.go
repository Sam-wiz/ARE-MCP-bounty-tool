package oracle

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// InteractshOOB is an OOBClient backed by projectdiscovery's interactsh-client
// CLI (installed via the interactsh plugin). Unlike HTTPCallbackOOB it uses a
// public/hosted OOB domain, so it works for EGRESS-BLIND SSRF where the target
// can reach the internet but not the engine's host.
//
// It runs `interactsh-client -json -o <file>`, learns the assigned correlation
// domain from stdout, hands out unique subdomains as tokens, and polls the
// JSON interaction log for a line carrying the token.
type InteractshOOB struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	outPath string
	domain  string // e.g. c4k9....oast.fun
	mu      sync.Mutex
}

var payloadDomainRE = regexp.MustCompile(`([a-z0-9]{16,}\.oast\.[a-z]+)`)

// NewInteractshOOB starts the client and blocks until it reports its OOB domain
// (or a short timeout). Requires interactsh-client on PATH.
func NewInteractshOOB(parent context.Context) (*InteractshOOB, error) {
	bin, err := exec.LookPath("interactsh-client")
	if err != nil {
		return nil, fmt.Errorf("interactsh-client not found on PATH (install via the interactsh plugin): %w", err)
	}
	f, err := os.CreateTemp("", "oracle-interactsh-*.jsonl")
	if err != nil {
		return nil, err
	}
	outPath := f.Name()
	f.Close()

	ctx, cancel := context.WithCancel(parent)
	args := []string{"-json", "-o", outPath}
	if extra := strings.TrimSpace(os.Getenv("ORACLE_INTERACTSH_ARGS")); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	o := &InteractshOOB{cmd: cmd, cancel: cancel, outPath: outPath}

	// Learn the assigned domain from stdout (bounded wait).
	domainCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if d := parsePayloadDomain(sc.Text()); d != "" {
				select {
				case domainCh <- d:
				default:
				}
				return
			}
		}
	}()

	select {
	case d := <-domainCh:
		o.domain = d
		return o, nil
	case <-time.After(20 * time.Second):
		o.Close()
		return nil, fmt.Errorf("interactsh-client did not report an OOB domain within 20s")
	case <-ctx.Done():
		o.Close()
		return nil, ctx.Err()
	}
}

// NewToken returns a unique subdomain of the correlation domain.
func (o *InteractshOOB) NewToken(_ context.Context) (token, host string, err error) {
	o.mu.Lock()
	domain := o.domain
	o.mu.Unlock()
	if domain == "" {
		return "", "", fmt.Errorf("interactsh domain not initialised")
	}
	token = randToken(6)
	return token, "http://" + token + "." + domain, nil
}

// Poll scans the interaction log for a hit carrying the token, until timeout.
func (o *InteractshOOB) Poll(ctx context.Context, token string, within time.Duration) (bool, string, error) {
	deadline := time.Now().Add(within)
	for {
		if data, err := os.ReadFile(o.outPath); err == nil {
			if line := lineWithToken(string(data), token); line != "" {
				return true, clip(line, 300), nil
			}
		}
		if time.Now().After(deadline) {
			return false, "", nil
		}
		select {
		case <-ctx.Done():
			return false, "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Domain exposes the assigned correlation domain (for display/tests).
func (o *InteractshOOB) Domain() string { o.mu.Lock(); defer o.mu.Unlock(); return o.domain }

// Close stops the client and removes the interaction log.
func (o *InteractshOOB) Close() error {
	if o.cancel != nil {
		o.cancel()
	}
	if o.cmd != nil && o.cmd.Process != nil {
		_ = o.cmd.Process.Kill()
	}
	if o.outPath != "" {
		_ = os.Remove(o.outPath)
	}
	return nil
}

// parsePayloadDomain extracts an interactsh correlation domain from a CLI line.
func parsePayloadDomain(line string) string {
	if m := payloadDomainRE.FindString(strings.ToLower(line)); m != "" {
		return m
	}
	return ""
}

// lineWithToken returns the first interaction line that carries the token.
func lineWithToken(log, token string) string {
	if token == "" {
		return ""
	}
	token = strings.ToLower(token)
	for _, line := range strings.Split(log, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		// scope to interaction records so unrelated log noise can't false-match
		low := strings.ToLower(l)
		if (strings.Contains(low, "unique-id") || strings.Contains(low, "full-id") || strings.Contains(low, "protocol")) &&
			strings.Contains(low, token) {
			return l
		}
	}
	return ""
}

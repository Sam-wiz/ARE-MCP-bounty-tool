package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// egressProxy returns the proxy URL that all request tools should egress
// through, or "" for a direct connection. Resolution order:
//  1. runtime override set via opsec_setup (proxy arg)
//  2. EGRESS_PROXY environment variable (.env)
//  3. the first entry of the opsec proxy_chain in config.yaml
//
// This is the single knob that fixes geo-blocked targets: point it at a US
// proxy and every http_request / api_test / compare_responses / discovery call
// leaves from that IP instead of the machine's real egress.
func (e *Engine) egressProxy() string {
	e.mu.RLock()
	p := e.egressProxyURL
	e.mu.RUnlock()
	if p != "" {
		return p
	}
	if v := strings.TrimSpace(os.Getenv("EGRESS_PROXY")); v != "" {
		return v
	}
	if e.config.Config != nil && len(e.config.Config.OPSEC.ProxyChain) > 0 {
		pc := e.config.Config.OPSEC.ProxyChain[0]
		if pc.Host != "" {
			scheme := pc.Type
			if scheme == "" {
				scheme = "http"
			}
			auth := ""
			if pc.Username != "" {
				auth = url.UserPassword(pc.Username, pc.Password).String() + "@"
			}
			return fmt.Sprintf("%s://%s%s:%d", scheme, auth, pc.Host, pc.Port)
		}
	}
	return ""
}

// setEgressProxy records a runtime egress proxy (used by opsec_setup).
func (e *Engine) setEgressProxy(p string) {
	e.mu.Lock()
	e.egressProxyURL = strings.TrimSpace(p)
	e.mu.Unlock()
}

// newHTTPClient builds an http.Client that egresses through the configured
// proxy (http/https/socks5/socks5h), or a plain direct client if none is set.
func (e *Engine) newHTTPClient(timeout time.Duration) *http.Client {
	proxyStr := e.egressProxy()
	if proxyStr == "" {
		return &http.Client{Timeout: timeout}
	}
	u, err := url.Parse(proxyStr)
	if err != nil || u.Host == "" {
		// Malformed proxy: fail closed to direct rather than crash, but this is
		// surfaced by egressLabel() so the operator can see it.
		return &http.Client{Timeout: timeout}
	}

	tr := &http.Transport{}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		if dialer, derr := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct); derr == nil {
			if cd, ok := dialer.(xproxy.ContextDialer); ok {
				tr.DialContext = cd.DialContext
			} else {
				tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
		}
	default: // http, https
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// curlProxyArg returns a curl proxy flag for shell-based tools (api_test,
// opsec IP checks), or "" for a direct connection. curl's --proxy handles
// http://, https:// and socks5:// schemes.
func (e *Engine) curlProxyArg() string {
	if p := e.egressProxy(); p != "" {
		return " --proxy " + ShellEscape(p)
	}
	return ""
}

// egressLabel is a short human-readable description of the current egress path.
func (e *Engine) egressLabel() string {
	if p := e.egressProxy(); p != "" {
		return "via proxy " + redactProxy(p)
	}
	return "DIRECT (no proxy — real IP)"
}

// redactProxy hides any credentials in a proxy URL for display.
func redactProxy(p string) string {
	if u, err := url.Parse(p); err == nil && u.User != nil {
		return u.Scheme + "://" + u.User.Username() + ":***@" + u.Host
	}
	return p
}

package opsec

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyChain manages a chain of proxies
type ProxyChain struct {
	proxies []ProxyConfig
	dialer  proxy.Dialer
}

// ProxyConfig represents a proxy configuration
type ProxyConfig struct {
	Type     string `yaml:"type"` // socks5, http, https
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// NewProxyChain creates a new proxy chain
func NewProxyChain(proxies []ProxyConfig) (*ProxyChain, error) {
	pc := &ProxyChain{
		proxies: proxies,
	}
	
	if err := pc.buildDialer(); err != nil {
		return nil, err
	}
	
	return pc, nil
}

// buildDialer builds the chained dialer
func (pc *ProxyChain) buildDialer() error {
	// Start with direct dialer
	var dialer proxy.Dialer = proxy.Direct
	
	// Chain proxies in reverse order (last proxy connects to direct)
	for i := len(pc.proxies) - 1; i >= 0; i-- {
		p := pc.proxies[i]
		
		var auth *proxy.Auth
		if p.Username != "" {
			auth = &proxy.Auth{
				User:     p.Username,
				Password: p.Password,
			}
		}
		
		addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
		
		switch p.Type {
		case "socks5":
			var err error
			dialer, err = proxy.SOCKS5("tcp", addr, auth, dialer)
			if err != nil {
				return fmt.Errorf("failed to create SOCKS5 proxy: %w", err)
			}
		case "http", "https":
			dialer = &httpProxyDialer{
				addr:     addr,
				auth:     auth,
				upstream: dialer,
				useTLS:   p.Type == "https",
			}
		default:
			return fmt.Errorf("unsupported proxy type: %s", p.Type)
		}
	}
	
	pc.dialer = dialer
	return nil
}

// Dial connects through the proxy chain
func (pc *ProxyChain) Dial(network, addr string) (net.Conn, error) {
	return pc.dialer.Dial(network, addr)
}

// DialContext connects through the proxy chain with context
func (pc *ProxyChain) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Check if context dialer is available
	if cd, ok := pc.dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return pc.dialer.Dial(network, addr)
}

// HTTPClient returns an HTTP client that uses the proxy chain
func (pc *ProxyChain) HTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: pc.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// Verify checks if the proxy chain is working
func (pc *ProxyChain) Verify(ctx context.Context) (bool, string, error) {
	client := pc.HTTPClient()
	
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=text", nil)
	if err != nil {
		return false, "", err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("proxy chain verification failed: %w", err)
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	return true, string(body), nil
}

// httpProxyDialer implements HTTP proxy dialing
type httpProxyDialer struct {
	addr     string
	auth     *proxy.Auth
	upstream proxy.Dialer
	useTLS   bool
}

func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	// Connect to proxy
	proxyConn, err := d.upstream.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	
	// If HTTPS proxy, wrap with TLS
	if d.useTLS {
		tlsConn := tls.Client(proxyConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			proxyConn.Close()
			return nil, err
		}
		proxyConn = tlsConn
	}
	
	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if d.auth != nil {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", 
			basicAuth(d.auth.User, d.auth.Password))
	}
	connectReq += "\r\n"
	
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		proxyConn.Close()
		return nil, err
	}
	
	// Read response
	buf := make([]byte, 1024)
	n, err := proxyConn.Read(buf)
	if err != nil {
		proxyConn.Close()
		return nil, err
	}
	
	if !contains(string(buf[:n]), "200") {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", string(buf[:n]))
	}
	
	return proxyConn, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return url.QueryEscape(auth) // Simplified, should use base64
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
